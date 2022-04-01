from setuptools import setup, find_packages


setup(
    name='ps4debug',
    version='0.0.1',
    author='Jay',
    author_email='Jay#4711',
    description='Integrates into Future Tone on the PS4',
    url='https://github.com/Jay184/PyPS4debug',
    project_urls={
        'Bug Tracker': 'https://github.com/Jay184/PyPS4debug/issues',
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    py_modules=['ps4debug'],
    include_package_data=True,
    entry_points='''
    ''',
    install_requires=[

    ],
    python_requires='>=3.10'
)
