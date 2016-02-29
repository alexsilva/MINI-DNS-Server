from __future__ import absolute_import

import mindns
import distutils.core

distutils.core.setup(
    name='Mini DNS',
    version=mindns.__version__,
    scripts=[
        'scripts/mdns.py',
    ],
    packages=[
        'mindns',
    ],
)
