"""VPS / datacenter providers — probe targets per country (Iran-focused selection)."""



from __future__ import annotations



from dataclasses import dataclass





@dataclass(frozen=True)

class ProviderProbe:

    name: str

    hosts: tuple[str, ...]

    asn_hint: str = ""

    dc_type: str = "vps"

    iran_notes: str = ""

    weight: float = 1.0





@dataclass(frozen=True)

class CountryCatalog:

    code: str

    providers: tuple[ProviderProbe, ...]





COUNTRY_CATALOG: dict[str, CountryCatalog] = {

    "Germany": CountryCatalog(

        code="DE",

        providers=(

            ProviderProbe("Hetzner", ("hetzner.com", "speed.hetzner.de"), "AS24940", "budget_vps", "Popular for REALITY/VPS from Iran", 1.15),

            ProviderProbe("OVH", ("ovh.com", "www.ovhcloud.com"), "AS16276", "premium_vps", "Good price; variable ping to IR", 1.0),

            ProviderProbe("Contabo", ("contabo.com",), "AS51167", "budget_vps", "Budget; sometimes oversubscribed", 0.9),

            ProviderProbe("Netcup", ("netcup.eu",), "AS197540", "budget_vps", "Relatively stable routes", 0.95),

            ProviderProbe("DigitalOcean", ("fra1.digitalocean.com",), "AS14061", "hyperscaler", "FRA1 region", 0.85),

            ProviderProbe("Vultr", ("fra-ping.vultr.com",), "AS20473", "budget_vps", "FRA ping endpoint", 0.9),

            ProviderProbe("Linode/Akamai", ("speedtest.frankfurt.linode.com",), "AS63949", "premium_vps", "Frankfurt", 0.85),

            ProviderProbe("Ionos", ("ionos.com",), "AS8560", "premium_vps", "DE brand VPS", 0.82),

            ProviderProbe("Scaleway", ("scaleway.com",), "AS12876", "budget_vps", "EU cloud alt", 0.78),

            ProviderProbe("M247", ("m247.com",), "AS9009", "colo_vps", "Carrier network", 0.8),

        ),

    ),

    "Netherlands": CountryCatalog(

        code="NL",

        providers=(

            ProviderProbe("Hetzner", ("hetzner.com",), "AS24940", "budget_vps", "Some NL nodes", 1.0),

            ProviderProbe("OVH", ("ovh.com",), "AS16276", "premium_vps", "", 1.0),

            ProviderProbe("DigitalOcean", ("ams3.digitalocean.com",), "AS14061", "hyperscaler", "AMS3", 0.9),

            ProviderProbe("Vultr", ("ams-ping.vultr.com",), "AS20473", "budget_vps", "", 0.9),

            ProviderProbe("Leaseweb", ("leaseweb.com",), "AS60781", "bare_metal", "Large NL DC", 0.85),

            ProviderProbe("Worldstream", ("worldstream.com",), "AS49981", "bare_metal", "NL dedicated", 0.83),

            ProviderProbe("TransIP", ("transip.eu",), "AS20857", "budget_vps", "Dutch VPS", 0.8),

            ProviderProbe("Cherry Servers", ("cherryservers.com",), "AS59642", "premium_vps", "EU NVMe", 0.78),

        ),

    ),

    "Finland": CountryCatalog(

        code="FI",

        providers=(

            ProviderProbe("Hetzner", ("hel1.hetzner.com", "hetzner.com"), "AS24940", "budget_vps", "HEL1 — often good path from Iran", 1.1),

            ProviderProbe("UpCloud", ("upcloud.com",), "AS202053", "premium_vps", "HEL region", 0.9),

            ProviderProbe("Google Cloud", ("storage.googleapis.com",), "AS15169", "hyperscaler", "heuristic FI edge", 0.7),

            ProviderProbe("Creanova", ("creanova.org",), "", "budget_vps", "FI local host", 0.72),

        ),

    ),

    "Turkey": CountryCatalog(

        code="TR",

        providers=(

            ProviderProbe("Turkcell DC", ("turkcell.com.tr",), "", "colo_vps", "Closest geography to Iran", 1.05),

            ProviderProbe("Natro", ("natro.com",), "", "budget_vps", "TR VPS", 0.85),

            ProviderProbe("Radore", ("radore.com",), "", "colo_vps", "TR colo", 0.82),

            ProviderProbe("OVH", ("ovh.com",), "AS16276", "premium_vps", "", 0.95),

            ProviderProbe("Contabo", ("contabo.com",), "AS51167", "budget_vps", "Sometimes TR exit", 0.85),

            ProviderProbe("Gcore", ("gcore.com",), "AS199524", "cdn_edge", "TR CDN/POP", 0.75),

        ),

    ),

    "France": CountryCatalog(

        code="FR",

        providers=(

            ProviderProbe("OVH", ("ovh.com", "www.ovhcloud.com"), "AS16276", "premium_vps", "HQ in France", 1.1),

            ProviderProbe("Scaleway", ("scaleway.com",), "AS12876", "budget_vps", "", 0.95),

            ProviderProbe("Online.net", ("online.net",), "AS12876", "bare_metal", "", 0.85),

            ProviderProbe("Hetzner", ("hetzner.com",), "AS24940", "budget_vps", "", 0.9),

            ProviderProbe("Ionos FR", ("ionos.fr",), "AS8560", "premium_vps", "", 0.8),

        ),

    ),

    "United Kingdom": CountryCatalog(

        code="GB",

        providers=(

            ProviderProbe("OVH UK", ("ovh.com",), "AS16276", "premium_vps", "London region", 0.88),

            ProviderProbe("M247 UK", ("m247.com",), "AS9009", "colo_vps", "UK network", 0.82),

            ProviderProbe("DigitalOcean", ("lon1.digitalocean.com",), "AS14061", "hyperscaler", "LON1", 0.8),

            ProviderProbe("Vultr", ("lon-ping.vultr.com",), "AS20473", "budget_vps", "London ping", 0.78),

        ),

    ),

    "United States": CountryCatalog(

        code="US",

        providers=(

            ProviderProbe("DigitalOcean", ("nyc3.digitalocean.com",), "AS14061", "hyperscaler", "NYC", 0.85),

            ProviderProbe("Vultr", ("nj-ping.vultr.com",), "AS20473", "budget_vps", "", 0.85),

            ProviderProbe("Linode", ("speedtest.newark.linode.com",), "AS63949", "premium_vps", "", 0.85),

            ProviderProbe("AWS", ("aws.amazon.com",), "AS16509", "hyperscaler", "heuristic", 0.75),

            ProviderProbe("BuyVM", ("buyvm.net",), "AS53667", "budget_vps", "Budget US", 0.68),

            ProviderProbe("RackNerd", ("racknerd.com",), "AS36352", "budget_vps", "Promo VPS", 0.62),

            ProviderProbe("ColoCrossing", ("colocrossing.com",), "AS36352", "budget_vps", "Budget", 0.6),

        ),

    ),

}



TARGET_COUNTRIES: tuple[str, ...] = tuple(COUNTRY_CATALOG.keys())



DC_TYPE_NAMES: dict[str, str] = {

    "budget_vps": "Budget VPS",

    "premium_vps": "Premium VPS",

    "hyperscaler": "Hyperscaler",

    "bare_metal": "Bare Metal",

    "colo_vps": "Colocation VPS",

    "cdn_edge": "CDN / Edge",

}


