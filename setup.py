import setuptools

setuptools.setup(
    name="ws_sdk",
    version="0.6.0.1",
    author="WhiteSource Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description="WS Python SDK",
    url='https://github.com/whitesource-ps/ws-sdk',
    license='LICENSE.txt',
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
    install_requires=[
        "DateTime",
        "requests",
        "requests-cache"
    ],
    extras_require={
        "spdx": ["spdx-tools"]
    },
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
