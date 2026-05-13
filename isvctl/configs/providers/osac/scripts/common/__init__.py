# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Shared Python utilities for OSAC provider scripts.

Every OSAC script reaches this package via a single ``sys.path`` entry -
``providers/osac/scripts/`` - so ``from common.osac_client import ...``
resolves without any namespace-package juggling. Modules:

- ``osac_client``: Keycloak admin + Fulfillment Service client helpers
  using only Python stdlib (``urllib.request``).
"""
