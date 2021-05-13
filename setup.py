import setuptools

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="ws_sdk",
    version="0.1.5",
    author="WhiteSource Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description="WS Python SDK",
    url='https://github.com/whitesource-ps/ws-sdk',
    license='LICENSE.txt',
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
    install_requires=open('requirements.txt').read().splitlines(),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
