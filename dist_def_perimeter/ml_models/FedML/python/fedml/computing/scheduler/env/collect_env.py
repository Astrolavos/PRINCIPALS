import os
import traceback

import GPUtil

import fedml
from fedml.computing.scheduler.slave.client_diagnosis import ClientDiagnosis


def collect_env():
    print("\n======== FedML (https://fedml.ai) ========")
    print("FedML version: " + str(fedml.__version__))
    env_version = fedml.get_env_version()
    print("FedML ENV version: " + str(env_version))
    
    print("Execution path:" + str(os.path.abspath(fedml.__file__)))

    print("\n======== Running Environment ========")
    import platform

    print("OS: " + platform.platform())
    print("Hardware: " + platform.machine())

    import sys

    print("Python version: " + sys.version)

    try:
        import torch
        print("PyTorch version: " + torch.__version__)
    except:
        print("PyTorch is not installed properly")

    try:
        import mpi4py
        mpi_obj = mpi4py.MPI
        print("MPI4py is installed")
    except:
        print("MPI4py is NOT installed")

    print("\n======== CPU Configuration ========")

    try:
        import psutil

        # Getting loadover15 minutes
        load1, load5, load15 = psutil.getloadavg()
        cpu_usage = (load15 / os.cpu_count()) * 100

        print("The CPU usage is : {:.0f}%".format(cpu_usage))
        print(
            "Available CPU Memory: {:.1f} G / {}G".format(
                psutil.virtual_memory().available / 1024 / 1024 / 1024,
                psutil.virtual_memory().total / 1024 / 1024 / 1024,
            )
        )
    except:
        print("\n")

    try:
        print("\n======== GPU Configuration ========")
        import GPUtil
        gpus = GPUtil.getGPUs()
        memory_total = 0.0
        memory_free = 0.0
        gpu_name = ""
        for gpu in gpus:
            memory_total += gpu.memoryTotal
            memory_free += gpu.memoryFree
            gpu_name = gpu.name

        print("NVIDIA GPU Info: " + gpu_name)
        print("Available GPU memory: {:.1f} G / {:.1f}G".format(
            memory_free / 1024.0, memory_total / 1024.0))

        import torch

        torch_is_available = torch.cuda.is_available()
        print("torch_is_available = {}".format(torch_is_available))

        device_count = torch.cuda.device_count()
        print("device_count = {}".format(device_count))

        device_name = torch.cuda.get_device_name(0)
        print("device_name = {}".format(device_name))

    except:
        print("No GPU devices")

    try:
        print("\n======== Network Connection Checking ========")
        is_open_connected = ClientDiagnosis.check_open_connection(None)
        url = fedml._get_backend_service()
        if is_open_connected:
            print(f"The connection to {url} is OK.\n")
        else:
            print(f"You can not connect to {url}.\n")

        is_s3_connected = ClientDiagnosis.check_s3_connection(None)
        if is_s3_connected:
            print("The connection to S3 Object Storage is OK.\n")
        else:
            print("You can not connect to S3 Object Storage.\n")

        is_mqtt_connected = ClientDiagnosis.check_mqtt_connection()
        mqtt_url = fedml._get_mqtt_service()
        if is_mqtt_connected:
            print(f"The connection to {mqtt_url} (port:1883) is OK.\n")
        else:
            print(f"You can not connect to {mqtt_url}.\n")
    except Exception as e:
        print(f"The connection exception: {traceback.format_exc()}")
        pass