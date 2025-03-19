from setuptools import setup, find_packages

setup(
    name="EnhancedPasswordManager",
    version="0.1",
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'bcrypt',
        'pycryptodome',
        'pandas',
        'openpyxl',
    ],
)
