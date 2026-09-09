"""Fixed-destination weather model tool with bounded city input."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import requests
from dotenv import load_dotenv
from livekit.agents import function_tool
from requests import RequestException

load_dotenv()
logger = logging.getLogger(__name__)

MAX_CITY_CHARACTERS = 120
REQUEST_TIMEOUT_SECONDS = 10
OPENWEATHER_URL = "https://api.openweathermap.org/data/2.5/weather"
_CITY_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,120}$")


def _validate_city(value: Any) -> str:
    """Validate a human-readable city; it is data, never a destination."""
    if not isinstance(value, str):
        raise ValueError("city must be text.")
    city = " ".join(value.split())
    if not city:
        raise ValueError("city is required; IP-based location lookup is disabled.")
    if len(city) > MAX_CITY_CHARACTERS or not _CITY_RE.fullmatch(city):
        raise ValueError("city must be at most 120 printable characters.")
    return city


@function_tool
async def get_weather(city: str = "") -> str:
    """Fetch weather for an explicitly supplied city from OpenWeather.

    No IP geolocation, arbitrary URL, host, proxy or network destination is
    accepted. The service endpoint is fixed in source and requests have a
    bounded timeout.
    """
    try:
        safe_city = _validate_city(city)
    except ValueError as exc:
        return f"Invalid weather request: {exc}"

    api_key = os.getenv("OPENWEATHER_API_KEY")
    if not api_key:
        logger.error("OpenWeather configuration is missing.")
        return "Weather is unavailable because required configuration is missing."

    logger.info("OpenWeather requested (city_length=%d).", len(safe_city))
    try:
        response = requests.get(
            OPENWEATHER_URL,
            params={"q": safe_city, "appid": api_key, "units": "metric"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except RequestException:
        logger.warning("OpenWeather request failed.")
        return "Weather is temporarily unavailable."
    status_code = response.status_code
    if not isinstance(status_code, int) or isinstance(status_code, bool) or not 100 <= status_code <= 599:
        logger.warning("OpenWeather returned an invalid HTTP status.")
        return "Weather returned an invalid response."
    if status_code != 200:
        logger.warning("OpenWeather returned HTTP %d.", status_code)
        return f"Weather is unavailable for the requested city (HTTP {status_code})."
    try:
        data = response.json()
        weather_items = data["weather"]
        primary = weather_items[0]
        description = str(primary["description"]).title()
        temperature = float(data["main"]["temp"])
        humidity = int(data["main"]["humidity"])
        wind_speed = float(data["wind"]["speed"])
    except (KeyError, IndexError, TypeError, ValueError):
        logger.warning("OpenWeather returned an invalid response.")
        return "Weather returned an invalid response."
    return (
        f"Weather in {safe_city}:\n"
        f"- Condition: {description}\n"
        f"- Temperature: {temperature:g}°C\n"
        f"- Humidity: {humidity}%\n"
        f"- Wind Speed: {wind_speed:g} m/s"
    )
