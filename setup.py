#!/usr/bin/env python

from setuptools import setup

setup(name='memfinder',
      version='0.1',
      description='Python tool to find a specific signature in a windows program memory and stop the program',
      author='Ilyas Semmaoui',
      author_email='none',
      url='none',
      packages=['memfinder'],
      package_dir={'memfinder': 'memfinder'},
      entry_points={'console_scripts': [
          'memfinder = memfinder.main:main',
      ]}
     )