from setuptools import setup, find_packages

setup(
    name='cyrebro_domain_validator',
    version='0.1.7',
    author='CYREBRO Innovation',
    author_email='innovation@cyrebro.io',
    description='A domain validation package, written by CYREBRO\'s Innovation team.',
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/pypa/cyrebro_domain_validator',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'requests',
        'dnspython>=2.2.1',
        'tld>=0.12.6'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Operating System :: OS Independent'

    ],
)
