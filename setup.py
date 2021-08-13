import setuptools

packages = ["pwmg"]

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pwmg",
    version="0.0.5",
    author="Fred Xia",
    author_email="fredxia2011@gmail.com",
    description="A password management tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fredxia/pwmg",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=packages,
    package_dir={"pwmg" : "pwmg"},
    python_requires=">=3.6",
    test_suite="tests",
    entry_points = {
        "console_scripts" : ["pwmg=pwmg.pwmg:main"],
    }
)
