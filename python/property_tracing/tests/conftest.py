# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
from pathlib import Path

# Make the property_tracing package importable when running pytest from any
# working directory.  The package directory is the parent of this tests/ dir.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
