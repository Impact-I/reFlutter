"""Setup script for reflutter"""

import setuptools


# Get version information without importing the package
SHORT_DESCRIPTION = 'Reverse Flutter'
LONG_DESCRIPTION = open('README.md', 'rt').read()

CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: Implementation :: PyPy',
    'Topic :: Software Development :: Build Tools',
]

setuptools.setup(
    name='reflutter',
    version='0.7.8',
    description=SHORT_DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author='impact',
    author_email='routeros7.1@gmail.com',
    url='https://github.com/Impact-I/reFlutter',
    packages=setuptools.find_packages(),
    license='GPLv3+',
    platforms=['any'],
    keywords='distutils setuptools egg pip requirements',
    classifiers=CLASSIFIERS,
    entry_points={
        'console_scripts': [
            'reflutter = src.__init__:main',
        ],
    },
)
