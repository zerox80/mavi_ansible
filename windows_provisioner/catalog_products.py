# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Microsoft-Produktkatalog.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    os,
    re,
    sys,
    yaml,
)




OFFICE_PRODUCTS: dict[str, dict[str, Any]] = {
    # Planner / Project subscription
    "project_plan3": {
        "name": "Planner and Project Plan 3",
        "product_id": "ProjectProRetail",
        "family": "project",
        "channel": None,
    },
    "project_plan5": {
        "name": "Planner and Project Plan 5",
        "product_id": "ProjectProRetail",
        "family": "project",
        "channel": None,
    },

    # Microsoft 365 / Office 365
    "m365_apps_enterprise": {
        "name": "Microsoft 365 Apps for enterprise (EEA / ohne Teams)",
        "product_id": "O365ProPlusEEANoTeamsRetail",
        "family": "office",
        "channel": None,
    },
    "m365_apps_business": {
        "name": "Microsoft 365 Apps for business (EEA / ohne Teams)",
        "product_id": "O365BusinessEEANoTeamsRetail",
        "family": "office",
        "channel": None,
    },
    "m365_business_standard": {
        "name": "Microsoft 365 Business Standard",
        "product_id": "O365BusinessRetail",
        "family": "office",
        "channel": None,
    },
    "m365_business_premium": {
        "name": "Microsoft 365 Business Premium",
        "product_id": "O365BusinessRetail",
        "family": "office",
        "channel": None,
    },
    "m365_e3_e5": {
        "name": "Microsoft 365 E3/E5 oder Office 365 E3/E5",
        "product_id": "O365ProPlusRetail",
        "family": "office",
        "channel": None,
    },

    # Office 2024 Retail / Volume
    "office_home_business_2024": {
        "name": "Office Home & Business 2024 Retail",
        "product_id": "HomeBusiness2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_professional_2024": {
        "name": "Office Professional 2024 Retail",
        "product_id": "Professional2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_proplus_2024_retail": {
        "name": "Office Professional Plus 2024 Retail",
        "product_id": "ProPlus2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_ltsc_proplus_2024": {
        "name": "Office LTSC Professional Plus 2024 Volume",
        "product_id": "ProPlus2024Volume",
        "family": "office",
        "channel": "PerpetualVL2024",
    },
    "office_ltsc_standard_2024": {
        "name": "Office LTSC Standard 2024 Volume",
        "product_id": "Standard2024Volume",
        "family": "office",
        "channel": "PerpetualVL2024",
    },

    # Project 2024
    "project_pro_2024_retail": {
        "name": "Project Professional 2024 Retail",
        "product_id": "ProjectPro2024Retail",
        "family": "project",
        "channel": None,
    },
    "project_std_2024_retail": {
        "name": "Project Standard 2024 Retail",
        "product_id": "ProjectStd2024Retail",
        "family": "project",
        "channel": None,
    },
    "project_pro_2024_volume": {
        "name": "Project Professional LTSC 2024 Volume",
        "product_id": "ProjectPro2024Volume",
        "family": "project",
        "channel": "PerpetualVL2024",
    },
    "project_std_2024_volume": {
        "name": "Project Standard LTSC 2024 Volume",
        "product_id": "ProjectStd2024Volume",
        "family": "project",
        "channel": "PerpetualVL2024",
    },

    # Visio
    "visio_subscription": {
        "name": "Visio Professional Subscription / Visio Plan 2",
        "product_id": "VisioProRetail",
        "family": "visio",
        "channel": None,
    },
    "visio_pro_2024_retail": {
        "name": "Visio Professional 2024 Retail",
        "product_id": "VisioPro2024Retail",
        "family": "visio",
        "channel": None,
    },
    "visio_std_2024_retail": {
        "name": "Visio Standard 2024 Retail",
        "product_id": "VisioStd2024Retail",
        "family": "visio",
        "channel": None,
    },
    "visio_pro_2024_volume": {
        "name": "Visio Professional LTSC 2024 Volume",
        "product_id": "VisioPro2024Volume",
        "family": "visio",
        "channel": "PerpetualVL2024",
    },
    "visio_std_2024_volume": {
        "name": "Visio Standard LTSC 2024 Volume",
        "product_id": "VisioStd2024Volume",
        "family": "visio",
        "channel": "PerpetualVL2024",
    },
}
