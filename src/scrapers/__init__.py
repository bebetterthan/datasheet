"""
Scrapers package - contains all source-specific scrapers.
"""

from .base_scraper import BaseScraper, ScrapedItem
from .hacktricks_scraper import HackTricksScraper
from .ctf_writeup_scraper import CTFWriteupScraper
from .exploit_db_scraper import ExploitDBScraper
from .cve_scraper import CVEScraper
from .nuclei_templates_scraper import NucleiTemplatesScraper
from .payloads_scraper import PayloadsScraper
from .owasp_scraper import OWASPScraper
from .portswigger_scraper import PortSwiggerScraper
from .sansec_scraper import SansecScraper
from .mitre_attack_scraper import MitreAttackScraper


# Registry of all available scrapers
SCRAPER_REGISTRY = {
    'hacktricks': HackTricksScraper,
    'ctf_writeups': CTFWriteupScraper,
    'exploit_db': ExploitDBScraper,
    'cve': CVEScraper,
    'nuclei_templates': NucleiTemplatesScraper,
    'payloads': PayloadsScraper,
    'owasp': OWASPScraper,
    'portswigger': PortSwiggerScraper,
    'sansec': SansecScraper,
    'mitre_attack': MitreAttackScraper,
}


def get_scraper(name: str):
    """Get scraper class by name."""
    return SCRAPER_REGISTRY.get(name)


def list_scrapers():
    """List all available scrapers."""
    return list(SCRAPER_REGISTRY.keys())


__all__ = [
    'BaseScraper',
    'ScrapedItem',
    'HackTricksScraper',
    'CTFWriteupScraper',
    'ExploitDBScraper',
    'CVEScraper',
    'NucleiTemplatesScraper',
    'PayloadsScraper',
    'OWASPScraper',
    'PortSwiggerScraper',
    'SansecScraper',
    'MitreAttackScraper',
    'SCRAPER_REGISTRY',
    'get_scraper',
    'list_scrapers',
]
