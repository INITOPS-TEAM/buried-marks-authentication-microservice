import os
import boto3
from django.db.backends.postgresql import base


def get_aws_connection_params(params):
    if "amazonaws.com" in os.environ.get("DB_HOST"):
        region_name = params.pop("region_name", os.environ.get("AWS_REGION"))
        rds_client = boto3.client(service_name="rds", region_name=region_name)

        hostname = params.get("host")
        hostname = hostname if hostname else "localhost"

        params["password"] = rds_client.generate_db_auth_token(
            DBHostname=hostname,
            Port=params.get("port", 5432),
            DBUsername=params.get("user", os.environ.get("DB_USER")),
        )

    return params

class DatabaseWrapper(base.DatabaseWrapper):
    def get_connection_params(self):
        params = super().get_connection_params()
        params.setdefault("port", 5432)
        return get_aws_connection_params(params)
