import setuptools


setuptools.setup(
    name="ws-sdk",
    version="0.1.0-1",
    author="WhiteSource Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description="WS Python SDK",
    url='https://github.com/whitesource-ps/ws-sdk',
    license='LICENSE',
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
    install_requires=open("requirements.txt").read(),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache License Version 2.0",
        "Operating System :: OS Independent",
    ],
)
