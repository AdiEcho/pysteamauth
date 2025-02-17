import setuptools
from setuptools import setup


requirements = [
    "aiohttp==3.11.12",
    "protobuf==5.29.3",
    "pydantic==2.10.6",
    "rsa==4.9",
    "bitstring==4.3.0",
    "urllib3==2.3.0",
]


setup(
    name="pysteamauth",
    version="1.1.2",
    url="https://github.com/sometastycake/pysteamauth",
    license="MIT",
    author="Mike M",
    author_email="stopthisworldplease@outlook.com",
    description="Asynchronous python library for Steam authorization using protobuf",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    zip_safe=False,
    python_requires=">=3.9",
    install_requires=requirements,
    setup_requires=requirements,
    include_package_data=True,
)
