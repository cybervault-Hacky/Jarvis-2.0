"""Phase 4 Windows power backend tests.

The Win32 modules are injected, so these tests exercise the real
:class:`WindowsPCPowerBackend` code paths on any operating system without ever
changing a real machine's power state.
"""

from __future__ import annotations

import unittest

from jarvis_devices.enums import Platform
from jarvis_devices.pc_power import (
    PCPowerBackendError,
    PowerPrivilegeError,
    UnsupportedPowerOperationError,
)
from jarvis_devices.pc_power_windows import (
    EWX_LOGOFF,
    EWX_POWEROFF,
    EWX_REBOOT,
    EWX_SHUTDOWN,
    SHUTDOWN_REASON,
    WindowsPCPowerBackend,
)

#: ``EWX_FORCE`` is deliberately *not* defined in the backend at all - JARVIS
#: never force-closes applications. The constant lives here so the tests can
#: prove that bit is never set on any call.
EWX_FORCE = 0x04
from jarvis_devices.pc_system import Capability

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_power_support import (
        FakeWin32Api,
        FakeWin32Con,
        FakeWin32Process,
        FakeWin32Security,
        Win32Error,
    )
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_power_support import (
        FakeWin32Api,
        FakeWin32Con,
        FakeWin32Process,
        FakeWin32Security,
        Win32Error,
    )


def backend(*, api=None, security=None, process=None, platform=Platform.PC, con=None):
    built = WindowsPCPowerBackend(
        api=api if api is not None else FakeWin32Api(),
        con=con if con is not None else FakeWin32Con(),
        security=security if security is not None else FakeWin32Security(),
        process=process if process is not None else FakeWin32Process(),
        platform_probe=lambda: platform,
    )
    return built, built._api, built._security


class AvailabilityTests(unittest.TestCase):
    def test_unavailable_off_pc(self) -> None:
        built, _, _ = backend(platform=Platform.ANDROID)
        self.assertFalse(built.is_available())
        self.assertIn("not on a PC", built.unavailable_reason())

    def test_unavailable_without_pywin32(self) -> None:
        built, _, _ = backend(api=None)
        built._api = None
        built._con = None
        self.assertFalse(built.is_available())
        self.assertIn("pywin32", built.unavailable_reason())

    def test_available_on_pc_with_pywin32(self) -> None:
        built, _, _ = backend()
        self.assertTrue(built.is_available())
        self.assertEqual(built.unavailable_reason(), "")


class CapabilityTests(unittest.TestCase):
    def test_a_full_laptop_supports_everything(self) -> None:
        built, _, _ = backend()
        self.assertEqual(
            built.capabilities(),
            {
                "shutdown": Capability.SUPPORTED,
                "restart": Capability.SUPPORTED,
                "logoff": Capability.SUPPORTED,
                "sleep": Capability.SUPPORTED,
                "hibernate": Capability.SUPPORTED,
                "sleep_detail": "",
                "hibernate_detail": "",
            },
        )

    def test_no_sleep_state_is_reported_as_unsupported(self) -> None:
        api = FakeWin32Api(capabilities={"SystemS1": False, "SystemS2": False, "SystemS3": False, "SystemS4": False, "HiberFilePresent": True})
        built, _, _ = backend(api=api)
        capabilities = built.capabilities()
        self.assertEqual(capabilities["sleep"], Capability.UNSUPPORTED)
        self.assertIn("S1-S4", capabilities["sleep_detail"])
        self.assertEqual(capabilities["hibernate"], Capability.SUPPORTED)

    def test_no_hibernation_file_is_reported_as_unsupported(self) -> None:
        api = FakeWin32Api(capabilities={"SystemS3": True, "HiberFilePresent": False})
        built, _, _ = backend(api=api)
        capabilities = built.capabilities()
        self.assertEqual(capabilities["hibernate"], Capability.UNSUPPORTED)
        self.assertIn("no hibernation file", capabilities["hibernate_detail"])
        self.assertEqual(capabilities["sleep"], Capability.SUPPORTED)

    def test_an_unreadable_capability_set_never_crashes(self) -> None:
        api = FakeWin32Api()
        api.capabilities_error = RuntimeError("WMI is down")
        built, _, _ = backend(api=api)
        capabilities = built.capabilities()
        self.assertEqual(capabilities["sleep"], Capability.UNSUPPORTED)
        self.assertEqual(capabilities["shutdown"], Capability.SUPPORTED)


class ExitWindowsTests(unittest.TestCase):
    def test_shutdown_uses_the_fixed_flags(self) -> None:
        built, api, _ = backend()
        built.shutdown()
        self.assertEqual(api.exit_windows_calls, [(EWX_SHUTDOWN | EWX_POWEROFF, SHUTDOWN_REASON)])

    def test_restart_uses_the_reboot_flag(self) -> None:
        built, api, _ = backend()
        built.restart()
        self.assertEqual(api.exit_windows_calls, [(EWX_REBOOT, SHUTDOWN_REASON)])

    def test_logoff_uses_the_logoff_flag(self) -> None:
        built, api, security = backend()
        built.logoff()
        self.assertEqual(api.exit_windows_calls, [(EWX_LOGOFF, SHUTDOWN_REASON)])
        # Logging out ends only the session - no privilege juggling required.
        self.assertEqual(security.opened_tokens, [])

    def test_force_is_never_used(self) -> None:
        built, api, _ = backend()
        built.logoff()
        built.shutdown()
        built.restart()
        for flags, _reason in api.exit_windows_calls:
            with self.subTest(flags=flags):
                self.assertEqual(flags & EWX_FORCE, 0, "EWX_FORCE must never be set")

    def test_shutdown_and_restart_enable_the_privilege_first(self) -> None:
        built, api, security = backend()
        built.shutdown()
        self.assertEqual(len(security.opened_tokens), 1)
        self.assertEqual(len(security.adjusted), 1)
        _handle, disable_all, new_state = security.adjusted[0]
        self.assertFalse(disable_all)
        self.assertEqual(new_state, [(("luid", "SeShutdownPrivilege"), 2)])
        self.assertEqual(api.closed_handles, [security.opened_tokens[0]])

    def test_a_refusal_becomes_a_backend_error(self) -> None:
        built, api, _ = backend()
        api.exit_windows_result = 0
        with self.assertRaises(PCPowerBackendError):
            built.shutdown()

    def test_a_missing_privilege_is_named_as_such(self) -> None:
        for winerror in (5, 1314):
            with self.subTest(winerror=winerror):
                built, api, _ = backend()
                api.exit_windows_error = Win32Error(winerror)
                with self.assertRaises(PowerPrivilegeError):
                    built.restart()

    def test_any_other_win32_error_is_a_plain_backend_error(self) -> None:
        built, api, _ = backend()
        api.exit_windows_error = Win32Error(1, "generic failure")
        with self.assertRaises(PCPowerBackendError) as caught:
            built.shutdown()
        self.assertNotIsInstance(caught.exception, PowerPrivilegeError)

    def test_a_failing_privilege_adjustment_is_not_fatal(self) -> None:
        """Best effort only - ExitWindowsEx remains the authority."""
        security = FakeWin32Security()
        security.raise_on_adjust = RuntimeError("cannot adjust this token")
        built, api, _ = backend(security=security)
        built.shutdown()
        self.assertEqual(api.exit_windows_calls, [(EWX_SHUTDOWN | EWX_POWEROFF, SHUTDOWN_REASON)])


class SuspendTests(unittest.TestCase):
    def test_sleep_suspends_without_forcing(self) -> None:
        built, api, _ = backend()
        built.sleep()
        self.assertEqual(api.suspend_calls, [(True, False)])

    def test_hibernate_does_not_suspend_and_never_forces(self) -> None:
        built, api, _ = backend()
        built.hibernate()
        self.assertEqual(api.suspend_calls, [(False, False)])

    def test_hibernation_without_a_hibernation_file_is_unsupported(self) -> None:
        api = FakeWin32Api(capabilities={"SystemS3": True, "HiberFilePresent": False})
        built, _, _ = backend(api=api)
        with self.assertRaises(UnsupportedPowerOperationError):
            built.hibernate()
        self.assertEqual(api.suspend_calls, [])

    def test_a_missing_suspend_api_is_unsupported(self) -> None:
        api = FakeWin32Api()
        api.SetSystemPowerState = None  # simulates an older Windows build
        built, _, _ = backend(api=api)
        for call in (built.sleep, built.hibernate):
            with self.subTest(call=call.__name__):
                with self.assertRaises(UnsupportedPowerOperationError):
                    call()

    def test_a_refused_suspend_is_a_backend_error(self) -> None:
        built, api, _ = backend()
        api.suspend_result = 0
        with self.assertRaises(PCPowerBackendError):
            built.sleep()

    def test_a_suspend_error_is_translated(self) -> None:
        built, api, _ = backend()
        api.suspend_error = Win32Error(5)
        with self.assertRaises(PowerPrivilegeError):
            built.sleep()


class NoRemoteTargetTests(unittest.TestCase):
    def test_the_backend_never_addresses_another_machine(self) -> None:
        """Every call is positional and machine local - there is nothing to target."""
        built, api, security = backend()
        built.logoff()
        built.shutdown()
        built.restart()
        built.sleep()
        built.hibernate()
        for flags, reason in api.exit_windows_calls:
            with self.subTest(flags=flags):
                self.assertIsInstance(flags, int)
                self.assertEqual(reason, SHUTDOWN_REASON)
        for suspend, force in api.suspend_calls:
            self.assertIsInstance(suspend, bool)
            self.assertIs(force, False)
        # The only other Win32 contact is the local process token.
        self.assertTrue(all(token[1] == 4242 for token in security.opened_tokens))

    def test_no_backend_method_accepts_a_parameter(self) -> None:
        import inspect

        for name in ("shutdown", "restart", "sleep", "hibernate", "logoff"):
            with self.subTest(method=name):
                signature = inspect.signature(getattr(WindowsPCPowerBackend, name))
                self.assertEqual(list(signature.parameters), ["self"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
