import setuptools


with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="explain_slack_bot",
    version="0.0.1",

    description="Explain is a system for definining common terms from within slack. You can also add new definitions.",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="Scott Hurrey",

    package_dir={"": "explain_slack_bot"},
    packages=setuptools.find_packages(where="explain_slack_bot"),

    install_requires=[
        "aws-cdk.core==1.96.0",
        "aws-cdk.aws-lambda",
        "aws-cdk.aws_apigateway",
        "aws-cdk.aws-apigatewayv2",
        "aws-cdk.aws-apigatewayv2-integrations",
        "aws-cdk.aws-dynamodb",
        "aws-cdk.custom-resources"
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "License :: OSI Approved :: Apache Software License",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
