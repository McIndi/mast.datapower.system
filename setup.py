import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="mast.datapower.system",
    version="2.0.4",
    author="Clifford Bressette",
    author_email="cliffordbressette@mcindi.com",
    description=("A Utility to work with the IBM DataPower"),
    license="GPLv3",
    keywords="DataPower system",
    url="http://github.com/mcindi/mast.system",
    namespace_packages=["mast", "mast.datapower"],
    packages=['mast', 'mast.datapower', 'mast.datapower.system'],
    entry_points={
        'mast_web_plugin': [
            'system=mast.datapower.system:WebPlugin'
        ]
    },
    data_files=[
        ("mast/datapower/system/data", [
            "./mast/datapower/system/docroot/plugin.js",
            "./mast/datapower/system/docroot/plugin.css"
        ])
    ],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Utilities",
        "License :: OSI Approved :: GPLv3",
    ],
)
