"""
Flask-S3-Custom
-------------
Link S3 to your file. Based on flask-s3 by e-dard

"""
from setuptools import setup


setup(
    name='Flask-S3-Custom',
    version='0.0.1',
    url='http://github.com/yuerany/flask-s3-custom',
    license='WTFPL',
    author='Yueran yuan',
    author_email='yueranyuan@gmail.com',
    description='Link S3 to your file. Based on flask-s3 by e-dard',
    long_description=__doc__,
    py_modules=['flask_s3_custom'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'Boto>=2.5.2'
    ],
    tests_require=['nose', 'mock'],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: Other/Proprietary License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
