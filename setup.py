import setuptools
from ws_sdk._version import __version__, __description__, __tool_name__

setuptools.setup(
    name=f"ws_{__tool_name__}",
    version=__version__,
    author="WhiteSource Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description=__description__,
    url='https://github.com/whitesource-ps/ws-sdk',
    license='LICENSE',
    packages=setuptools.find_packages(),
    python_requires='>=3.7',
    install_requires=[line.strip() for line in open("requirements.txt").readlines()],
    extras_require={
        "spdx": ["spdx-tools"]
    },
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
