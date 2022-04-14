from setuptools import setup, find_packages


with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='ps4debug',
    version='0.0.8',
    author='Jay',
    author_email='0jaybae0@gmail.com',
    description='Integrates into Future Tone on the PS4',
    long_description=long_description,
    long_description_content_type='text/markdown',
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
        'construct',
    ],
    python_requires='>=3.10'
)
