"""Build tunnel route display (client → server countries)."""

from __future__ import annotations

from backend.models import IPIntelligence, TunnelRoute
from network.geo import lookup_client_geo
from utils.country import country_flag, format_country


async def build_tunnel_route(server_ips: list[IPIntelligence]) -> TunnelRoute:
    """Detect client and server countries for tunnel display."""
    route = TunnelRoute()
    client_geo = await lookup_client_geo()

    if client_geo:
        route.client_ip = client_geo.get("ip")
        route.client_country = client_geo.get("country")
        route.client_country_code = client_geo.get("country_code")
        route.client_country_flag = country_flag(route.client_country_code)
        route.client_city = client_geo.get("city")

    if server_ips:
        srv = server_ips[0]
        route.server_ip = srv.ip
        route.server_country = srv.country
        route.server_country_code = srv.country_code
        route.server_country_flag = srv.country_flag or country_flag(srv.country_code)
        route.server_city = srv.city

    client_display = format_country(route.client_country_code, route.client_country)
    server_display = format_country(route.server_country_code, route.server_country)

    if route.client_country_code and route.server_country_code:
        c_flag = route.client_country_flag or "🏳️"
        s_flag = route.server_country_flag or "🏳️"
        route.route_display = f"{c_flag} {route.client_country or '?'}  →  {s_flag} {route.server_country or '?'}"
    elif route.server_country_code:
        route.route_display = f"?  →  {server_display}"
    else:
        route.route_display = "Country data unavailable"

    return route
