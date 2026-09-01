"""
formatting.py — reformatări text partajate între filtrele Jinja (webapp.py) și
exportul .xlsx (xlsx_export.py), ca cele două să rămână mereu în acord (dacă
se schimbă formatul unei date, se schimbă într-un singur loc).
"""


def fmt_dt(value):
    """'2026-08-26T09:14:03+03:00' -> '26.08.2026 09:14' — fără conversii de
    fus, doar reformatare pentru citire (§6: timpii rămân exact cum vin din
    colector)."""
    if not value:
        return "—"
    try:
        date_part, time_part = value.split("T")
        y, m, d = date_part.split("-")
        hh_mm = time_part[:5]
        return f"{d}.{m}.{y} {hh_mm}"
    except (ValueError, IndexError):
        return value


def fmt_bool(value, yes="da", no="nu"):
    if value is None:
        return "—"
    return yes if value else no
