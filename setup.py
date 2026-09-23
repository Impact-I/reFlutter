"""Setup script for reflutter"""

import setuptools


# Get version information without importing the package
SHORT_DESCRIPTION = "Reverse Flutter"
LONG_DESCRIPTION = open("README.md", "rt").read()

CLASSIFIERS = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
]

setuptools.setup(
    name="reflutter",
    version="0.9.0",
    description=SHORT_DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author="impact",
    author_email="routeros7.1@gmail.com",
    url="https://github.com/Impact-I/reFlutter",
    packages=["reflutter"],
    package_data={"reflutter": ["frida.js"]},
    license="GPLv3+",
    platforms=["any"],
    keywords="distutils setuptools egg pip requirements",
    classifiers=CLASSIFIERS,
    entry_points={
        "console_scripts": [
            "reflutter = reflutter.__init__:main",
        ],
    },
    python_requires=">=3.10",
)
