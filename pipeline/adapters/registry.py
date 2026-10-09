"""Import hub: importing this module registers every adapter. Use these names:

    from pipeline.adapters.registry import detect_dataset, get_adapter, list_adapters
"""
from __future__ import annotations

from pipeline.adapters import (  # noqa: F401  (imports register the adapters)
    cicids2017_adapter,
    cicids2018_adapter,
    ctu13_adapter,
    stubs,
    unsw_nb15_adapter,
)
from pipeline.adapters.base import (  # noqa: F401
    CANONICAL_COLUMNS,
    CONTRACT_VERSION,
    DatasetAdapter,
    Detection,
    ReadStats,
    check_canonical_frame,
    detect_dataset,
    detect_file_adapter,
    get_adapter,
    list_adapters,
    register_adapter,
)
