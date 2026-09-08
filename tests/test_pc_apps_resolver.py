"""Application catalog + resolver tests (Phase 2)."""

from __future__ import annotations

import unittest

from jarvis_devices import ErrorCode
from jarvis_devices.pc_apps import (
    ApplicationCatalog,
    ApplicationResolver,
    ApplicationSpec,
    WindowInfo,
    default_application_catalog,
    match_windows,
)


class ApplicationSpecValidationTests(unittest.TestCase):
    def test_valid_spec_is_accepted(self) -> None:
        spec = ApplicationSpec(
            name="chrome",
            display_name="Google Chrome",
            aliases=("Google Chrome", "chrome browser"),
            launch_target="chrome.exe",
            search_paths=(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe",),
            process_names=("chrome.exe",),
        )
        self.assertEqual(spec.aliases, ("google chrome", "chrome browser"))
        self.assertEqual(spec.name, "chrome")

    def test_search_paths_keep_their_case(self) -> None:
        spec = ApplicationSpec(name="vlc", display_name="VLC", launch_target=r"C:\VLC\vlc.exe")
        self.assertEqual(spec.search_paths, ())
        spec2 = ApplicationSpec(
            name="vlc", display_name="VLC", search_paths=(r"%PROGRAMFILES%\VideoLAN\VLC\vlc.exe",)
        )
        self.assertIn("VideoLAN", spec2.search_paths[0])

    def test_invalid_name_is_rejected(self) -> None:
        for bad in ("", "Bad Name", "1app", "app;rm"):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    ApplicationSpec(name=bad, display_name="X", launch_target="x.exe")

    def test_missing_display_name_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ApplicationSpec(name="app", display_name="   ", launch_target="x.exe")

    def test_spec_without_any_target_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ApplicationSpec(name="app", display_name="App")

    def test_shell_operators_in_a_launch_target_are_rejected(self) -> None:
        for bad in (
            "notepad.exe & calc.exe",
            "notepad.exe; rm -rf /",
            "powershell.exe -c x",
            'cmd.exe /c "dir"',
            "app.exe | more",
            "app.exe > out.txt",
            "$(reboot)",
            "app.exe\nshutdown",
            "notepad with args.exe",
        ):
            with self.subTest(target=bad):
                with self.assertRaises(ValueError):
                    ApplicationSpec(name="app", display_name="App", launch_target=bad)

    def test_shell_operators_in_a_search_path_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ApplicationSpec(
                name="app",
                display_name="App",
                search_paths=(r"C:\Apps\app.exe & calc.exe",),
            )

    def test_non_exe_targets_must_be_a_registered_uri(self) -> None:
        with self.assertRaises(ValueError):
            ApplicationSpec(name="app", display_name="App", launch_target="some-script")
        spec = ApplicationSpec(name="settings", display_name="Settings", launch_target="ms-settings:")
        self.assertEqual(spec.launch_target, "ms-settings:")

    def test_search_paths_must_point_at_executables(self) -> None:
        with self.assertRaises(ValueError):
            ApplicationSpec(name="app", display_name="App", search_paths=(r"C:\Apps\payload.txt",))


class ApplicationCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_application_catalog()

    def test_default_catalog_contains_the_documented_applications(self) -> None:
        for name in ("chrome", "notepad", "calculator", "explorer", "vs-code", "settings"):
            with self.subTest(app=name):
                self.assertIn(name, self.catalog)

    def test_no_shell_is_catalogued(self) -> None:
        """Launching cmd/PowerShell would be arbitrary command execution."""
        names = " ".join(self.catalog.names())
        targets = " ".join(
            spec.launch_target.lower() for spec in self.catalog.all()
        )
        for forbidden in ("cmd", "powershell", "shell", "terminal"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, names)
                self.assertNotIn(forbidden + ".exe", targets)

    def test_duplicate_names_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.add(ApplicationSpec(name="chrome", display_name="Other", launch_target="x.exe"))

    def test_add_and_remove(self) -> None:
        spec = ApplicationSpec(name="spotify", display_name="Spotify", launch_target="spotify.exe")
        self.catalog.add(spec)
        self.assertIs(self.catalog.get("spotify"), spec)
        self.assertTrue(self.catalog.remove("SPOTIFY"))
        self.assertIsNone(self.catalog.get("spotify"))
        self.assertFalse(self.catalog.remove("spotify"))

    def test_rejects_non_spec_objects(self) -> None:
        with self.assertRaises(TypeError):
            self.catalog.add({"name": "nope"})  # type: ignore[arg-type]


class ApplicationResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = ApplicationResolver(default_application_catalog())

    def test_exact_match(self) -> None:
        self.assertEqual(self.resolver.resolve("notepad").spec.name, "notepad")

    def test_case_insensitive_match(self) -> None:
        self.assertEqual(self.resolver.resolve("  NoTePaD ").spec.name, "notepad")

    def test_alias_resolution(self) -> None:
        for query, expected in (
            ("google chrome", "chrome"),
            ("vscode", "vs-code"),
            ("vs code", "vs-code"),
            ("visual studio code", "vs-code"),
            ("calc", "calculator"),
            ("file explorer", "explorer"),
            ("windows settings", "settings"),
            ("ms paint", "paint"),
        ):
            with self.subTest(query=query):
                resolution = self.resolver.resolve(query)
                self.assertTrue(resolution.ok)
                self.assertEqual(resolution.spec.name, expected)

    def test_quoted_query_is_trimmed(self) -> None:
        self.assertEqual(self.resolver.resolve('"Chrome"').spec.name, "chrome")

    def test_unique_prefix_match(self) -> None:
        self.assertEqual(self.resolver.resolve("note").spec.name, "notepad")
        self.assertEqual(self.resolver.resolve("chrom").spec.name, "chrome")

    def test_unknown_application(self) -> None:
        resolution = self.resolver.resolve("blorp")
        self.assertFalse(resolution.ok)
        self.assertIsNone(resolution.spec)
        self.assertEqual(resolution.error_code, ErrorCode.APPLICATION_NOT_FOUND)
        self.assertIn("blorp", resolution.message)

    def test_typos_are_corrected(self) -> None:
        for query, expected in (("chromee", "chrome"), ("notepadd", "notepad"), ("calclator", "calculator")):
            with self.subTest(query=query):
                resolution = self.resolver.resolve(query)
                self.assertTrue(resolution.ok)
                self.assertEqual(resolution.spec.name, expected)

    def test_a_merely_similar_name_is_suggested_not_accepted(self) -> None:
        """Chromium is not Chrome: JARVIS must not act on a guess."""
        for query in ("chromium", "internet explorer"):
            with self.subTest(query=query):
                resolution = self.resolver.resolve(query)
                self.assertFalse(resolution.ok)
                self.assertEqual(resolution.error_code, ErrorCode.APPLICATION_NOT_FOUND)
                self.assertIn("Did you mean", resolution.message)

    def test_ambiguous_application_is_not_guessed(self) -> None:
        resolution = self.resolver.resolve("c")
        self.assertFalse(resolution.ok)
        self.assertEqual(resolution.error_code, ErrorCode.AMBIGUOUS_APPLICATION)
        self.assertGreater(len(resolution.candidates), 1)
        self.assertIn("more than one application", resolution.message)

    def test_empty_query_is_an_invalid_argument(self) -> None:
        for query in ("", "   ", None):
            with self.subTest(query=query):
                resolution = self.resolver.resolve(query)
                self.assertEqual(resolution.error_code, ErrorCode.INVALID_ARGUMENT)

    def test_empty_catalog_reports_not_found(self) -> None:
        resolver = ApplicationResolver(ApplicationCatalog())
        self.assertEqual(resolver.resolve("chrome").error_code, ErrorCode.APPLICATION_NOT_FOUND)

    def test_normalize_never_interprets_content(self) -> None:
        self.assertEqual(
            ApplicationResolver.normalize("  Google   Chrome && calc.exe "),
            "google chrome && calc.exe",
        )


class WindowMatchingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chrome = default_application_catalog().get("chrome")
        self.notepad = default_application_catalog().get("notepad")

    def test_matches_by_process_name(self) -> None:
        window = WindowInfo(handle=1, title="New Tab", process_name="chrome.exe")
        self.assertEqual(match_windows(self.chrome, [window])[0].handle, 1)

    def test_matches_by_window_title(self) -> None:
        window = WindowInfo(handle=2, title="Google Chrome - incognito", process_name="")
        self.assertEqual(match_windows(self.chrome, [window])[0].handle, 2)

    def test_ignores_hidden_windows_and_other_applications(self) -> None:
        windows = [
            WindowInfo(handle=3, title="Untitled - Notepad", process_name="notepad.exe"),
            WindowInfo(handle=4, title="Google Chrome", process_name="chrome.exe", is_visible=False),
        ]
        self.assertEqual(match_windows(self.chrome, windows), ())
        self.assertEqual([w.handle for w in match_windows(self.notepad, windows)], [3])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
