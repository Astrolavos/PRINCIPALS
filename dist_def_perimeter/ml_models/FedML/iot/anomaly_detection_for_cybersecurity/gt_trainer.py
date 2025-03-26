import logging
import os
from model.autoencoder import AutoEncoder
import numpy as np
import pandas as pd
import torch
import time
import torch.nn as nn
import glob
import itertools

def compute_min_max(dir_list):
    max_filename="max.txt"
    min_filename="min.txt"
    if os.path.isfile(max_filename) and os.path.isfile(min_filename):
        return
    else:
        print("computing min/max")

    L_max = []
    for d in dir_list:
        file_list = glob.glob(d+"/*")
        for f in file_list:
            df = pd.read_csv(f)
            L_max.append(df.max().to_frame().T)
    df = pd.concat(L_max)
    df.max().to_csv("tmp.csv")
    os.system(f"less tmp.csv | tail -n +2| cut -d, -f 2 > {max_filename}")

    L_min = []
    for d in dir_list:
        file_list = glob.glob(d+"/*")
        for f in file_list:
            df = pd.read_csv(f)
            L_min.append(df.min().to_frame().T)
    df = pd.concat(L_min)
    df.min().to_csv("tmp.csv")
    os.system(f"less tmp.csv | tail -n +2| cut -d, -f 2 > {min_filename}")

    os.system("rm -rf tmp.csv")


def get_data(data_file,min_file="min.txt",max_file="max.txt",start=None, end=None, batch_size=10):
    max_dataset = np.loadtxt(max_file)
    min_dataset = np.loadtxt(min_file)
    data = pd.read_csv(data_file)
    if start or end:
        data = data[start:end]
    data = np.array(data)
    data[np.isnan(data)] = 0
    data = (data - min_dataset) / (max_dataset - min_dataset)
    return torch.utils.data.DataLoader(
                data, batch_size=batch_size, shuffle=False, num_workers=0
    ),data.shape[1],data

    
        

def load_data(args, device_ids=None):
    min_max_file_path="."
    min_dataset = np.loadtxt(os.path.join(min_max_file_path, "max.txt"))
    max_dataset = np.loadtxt(os.path.join(min_max_file_path, "min.txt"))


    train_data_dict = {}
    benign_th_dict = {}
    test_data_dict = {}
    raw_data = {}
    

    for device in device_ids:
        device_data_cache_dir = os.path.join(args['data_cache_dir'], args['train_day'], device + ".csv")
        benign_data = pd.read_csv(device_data_cache_dir)
        #benign_data = benign_data.drop('Unnamed: 0',axis=1)
        #if len(benign_data) < 8000:
        #    print("Not enough data", len(benign_data), device)
        #    exit(1)
        benign_data = benign_data[:5000]
        benign_data = np.array(benign_data)
        benign_data[np.isnan(benign_data)] = 0
        benign_data = (benign_data - min_dataset) / (max_dataset - min_dataset)
        #x = benign_data
        #x = x[:, ~np.isnan(x).any(axis=0)]
        #benign_data = x
        #print(x.shape)

        

        train_data_dict[device] = torch.utils.data.DataLoader(
            benign_data, batch_size=args['batch_size'], shuffle=False, num_workers=0
        )
        raw_data["train_data"] = benign_data

        benign_data = pd.read_csv(device_data_cache_dir)
        #benign_data = benign_data.drop('Unnamed: 0',axis=1)
        benign_data = benign_data[5000:8000]
        benign_data = np.array(benign_data)
        benign_data[np.isnan(benign_data)] = 0
        benign_data = (benign_data - min_dataset) / (max_dataset - min_dataset)
        #x = benign_data
        #x = x[:, ~np.isnan(x).any(axis=0)]
        #benign_data = x
        #print(x.shape)

        benign_th_dict[device] = torch.utils.data.DataLoader(
            benign_data,  batch_size=128, shuffle=False, num_workers=0
        )
        raw_data["th_data"] = benign_data


        device_data_cache_dir = os.path.join(args['data_cache_dir'], args['test_day'], args['test_device'] + ".csv")
        attack_data = pd.read_csv(device_data_cache_dir)
        #attack_data = attack_data.drop('Unnamed: 0',axis=1)

        attack_data = np.array(attack_data)
        attack_data[np.isnan(attack_data)] = 0
        attack_data = (attack_data - min_dataset) / (max_dataset - min_dataset)
        #x = attack_data
        #x = x[:, ~np.isnan(x).any(axis=0)]
        #attack_data = x
        #print(x.shape)

        test_data_dict[device] = torch.utils.data.DataLoader(
                attack_data, batch_size=args['batch_size'], shuffle=False, num_workers=0
        )
        raw_data["test_data"] = attack_data

    
    class_num = attack_data.shape[1]
    print("class_num", class_num)

    dataset = {}

    dataset["train_data"] = train_data_dict
    dataset["test_data"] = test_data_dict
    dataset["benign_th"] = benign_th_dict
    return dataset, raw_data, class_num



def load_data_old(args, device_ids=None):
    device_list = [
        "Danmini_Doorbell",
        "Ecobee_Thermostat",
        "Ennio_Doorbell",
        "Philips_B120N10_Baby_Monitor",
        "Provision_PT_737E_Security_Camera",
        "Provision_PT_838_Security_Camera",
        "Samsung_SNH_1011_N_Webcam",
        "SimpleHome_XCS7_1002_WHT_Security_Camera",
        "SimpleHome_XCS7_1003_WHT_Security_Camera",
    ]

    train_data_dict = dict.fromkeys(range(9))
    train_data_batch_num_dict = dict.fromkeys(range(9))
    test_data_dict = dict.fromkeys(range(9))
    train_data_num = 0
    benign_th_dict = dict.fromkeys(range(9))

    min_max_file_path = "./data"
    min_dataset = np.loadtxt(os.path.join(min_max_file_path, "min_dataset.txt"))
    max_dataset = np.loadtxt(os.path.join(min_max_file_path, "max_dataset.txt"))

    for i, device_name in enumerate(device_list):
        if device_ids and i not in device_ids:
            continue
        print(device_name, i)
        device_data_cache_dir = os.path.join(args['data_cache_dir'], device_name)

        logging.info("Creating dataset {}".format(device_name))
        benign_data = pd.read_csv(
            os.path.join(device_data_cache_dir, "benign_traffic.csv")
        )
        ###### get train data ######
        benign_data = benign_data[:5000]
        benign_data = np.array(benign_data)
        benign_data[np.isnan(benign_data)] = 0
        benign_data = (benign_data - min_dataset) / (max_dataset - min_dataset)

        train_data_dict[i] = torch.utils.data.DataLoader(
            benign_data, batch_size=args['batch_size'], shuffle=False, num_workers=0
        )
        train_data_batch_num_dict[i] = len(
            train_data_dict[i]
        )
        ###### get threshold data ######
        benign_data = pd.read_csv(
            os.path.join(args['data_cache_dir'], device_name, "benign_traffic.csv")
        )
        benign_data = np.array(benign_data)

        benign_th = benign_data[5000:8000]
        benign_th[np.isnan(benign_th)] = 0
        benign_th = (benign_th - min_dataset) / (max_dataset - min_dataset)

        benign_th_dict[i] = torch.utils.data.DataLoader(
            benign_th, batch_size=128, shuffle=False, num_workers=0
        ) 
        ###### get malicious data ######
        g_attack_data_list = [
                os.path.join(args['data_cache_dir'], device_name, "gafgyt_attacks", f)
                for f in os.listdir(
                    os.path.join(args['data_cache_dir'], device_name, "gafgyt_attacks")
                )
        ]
        if (
            device_name == "Ennio_Doorbell"
            or device_name == "Samsung_SNH_1011_N_Webcam"
        ):
            attack_data_list = g_attack_data_list
        else:
            m_attack_data_list = [
                os.path.join(args['data_cache_dir'], device_name, "mirai_attacks", f)
                for f in os.listdir(
                    os.path.join(args['data_cache_dir'], device_name, "mirai_attacks")
                )
            ]
            attack_data_list = g_attack_data_list + m_attack_data_list
        print(attack_data_list)
        attack_data = pd.concat([pd.read_csv(f)[:500] for f in attack_data_list])
        attack_data = (attack_data - attack_data.mean()) / (attack_data.std())
        attack_data = np.array(attack_data)
        attack_data[np.isnan(attack_data)] = 0

        test_data_dict[i] = torch.utils.data.DataLoader(
                attack_data, batch_size=args['batch_size'], shuffle=False, num_workers=0
        )

    class_num = 115
    dataset = [
        train_data_batch_num_dict,
        train_data_dict,
        test_data_dict,
        benign_th_dict,
        class_num,
    ]
    return dataset, class_num

def train_model(model, train_data):
    learning_rate =  0.03#0.03
    device='cpu'
    epochs = 5
    tick = time.time()
    model.to(device)
    model.train()

    # train and update
    criterion = nn.MSELoss().to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    epoch_loss = []
    for epoch in range(epochs):
        batch_loss = []
        for batch_idx, x in enumerate(train_data):
            x = x.to(device).float()
            optimizer.zero_grad()
            decode = model(x)
            loss = criterion(decode, x)
            loss.backward()
            optimizer.step()

            # logging.info(
            #     "Update Epoch: {} [{}/{} ({:.0f}%)]\tLoss: {:.6f}".format(
            #         epoch,
            #         (batch_idx + 1) * args.batch_size,
            #         len(train_data) * args.batch_size,
            #         100.0 * (batch_idx + 1) / len(train_data),
            #         loss.item(),
            #     )
            # )
            batch_loss.append(loss.item())
        epoch_loss.append(sum(batch_loss) / len(batch_loss))
        #print("Client \tEpoch: {}\tLoss: {:.6f}".format(epoch, sum(epoch_loss) / len(epoch_loss)))

    print("Train/Time:", time.time() - tick)
    return

def get_local_threshold(model, train_data):
    device='cpu'
    model.to(device)
    model.eval()
    mse = list()
    threshold_func = nn.MSELoss(reduction="none")
    for batch_idx, x in enumerate(train_data):
        x = x.to(device).float()
        diff = threshold_func(model(x), x)
        mse.append(diff)
    mse_global = torch.cat(mse).mean(dim=1)
    threshold_global = torch.mean(mse_global) + 3 * torch.std(mse_global)
    return threshold_global


def test_model(model, train_data, test_data, threshold, printres=False):
    device='cpu'
    model.to(device)
    model.eval()

    true_negative = 0
    false_positive = 0
    true_positive = 0
    false_negative = 0

    threshold_func = nn.MSELoss(reduction="none")

    for batch_idx, x in enumerate(train_data):
        x = x.to(device).float()
        diff = threshold_func(model(x), x)
        mse = diff.mean(dim=1)
        false_positive += sum(mse > threshold)
        true_negative += sum(mse <= threshold)

    for batch_idx, x in enumerate(test_data):
        x = x.to(device).float()
        diff = threshold_func(model(x), x)
        mse = diff.mean(dim=1)
        true_positive += sum(mse > threshold)
        false_negative += sum(mse <= threshold)

    accuracy = (true_positive + true_negative) / (
        true_positive + true_negative + false_positive + false_negative
    )

    precision = true_positive / (true_positive + false_positive)
    false_positive_rate = false_positive / (false_positive + true_negative)
    tpr = true_positive / (true_positive + false_negative)
    tnr = true_negative / (true_negative + false_positive)

    if printres:
        print("The True negative number is {}".format(true_negative))
        print("The False positive number is {}".format(false_positive))
        print("The True positive number is {}".format(true_positive))
        print("The False negative number is {}".format(false_negative))

        print("The accuracy is {}".format(accuracy))
        print("The precision is {}".format(precision))
        print("The false positive rate is {}".format(false_positive_rate))
        print("tpr is {}".format(tpr))
        print("tnr is {}".format(tnr))
    return tpr,tnr,accuracy,precision

if __name__ == "__main__":

    #args = {
    #    'batch_size' : 10,
    #    'data_cache_dir' : '/mnt/fediot_data',
    #    'device_id': 1,
    #}

    args = {
            'batch_size' : 10,
            'data_cache_dir' : 'parsed_data',
            'train_day' : '11',
            'test_day' : '12',
            'device_id': 1,
        }



    compute_min_max(['parsed_data/10','parsed_data/11','parsed_data/12'])
    ip_list = ["192.168.0.12","192.168.0.13","192.168.0.15","192.168.0.18","192.168.0.23","192.168.0.33","192.168.0.35","192.168.0.38","192.168.0.39","192.168.0.47","192.168.0.48","192.168.0.52","192.168.0.8"]
    #ip_list =  ["192.168.0.13","192.168.0.18","192.168.0.48"]
    res = []

    user1="192.168.0.12"
    user2="192.168.0.38"
    for user1, user2 in list(itertools.combinations(ip_list,2)):
        train_data_filename = os.path.join(args['data_cache_dir'], args['train_day'], user1 + ".csv")
        test_data_filename = os.path.join(args['data_cache_dir'], args['test_day'], user1 + ".csv")

        train_data1, _, _ = get_data(train_data_filename,start=0, end=5000)
        threshold_data1, _, _ = get_data(train_data_filename,start=5000, end=8000, batch_size=128)
        test_data1, dims, _ = get_data(test_data_filename)

        train_data_filename = os.path.join(args['data_cache_dir'], args['train_day'], user2 + ".csv")
        test_data_filename = os.path.join(args['data_cache_dir'], args['test_day'], user2 + ".csv")

        train_data2, _, _ = get_data(train_data_filename,start=0, end=5000)
        threshold_data2, _, _ = get_data(train_data_filename,start=5000, end=8000, batch_size=128)
        test_data2, dims, _ = get_data(test_data_filename)

        model1 = AutoEncoder(dims)
        train_model(model1, train_data1)
        tr1 = get_local_threshold(model1, threshold_data1)
        tpr,tnr,accuracy,precision = test_model(model1, train_data1,  test_data1, tr1)
        if tpr > 0.3 or tnr < 0.5:
            continue
        tpr,tnr,accuracy,precision = test_model(model1, train_data1,  test_data2, tr1)
        if tpr < 0.6 or tnr < 0.5:
            continue
        #print("-----")
        model2 = AutoEncoder(dims)
        train_model(model2, train_data2)
        tr2 = get_local_threshold(model2, threshold_data2)
        tpr,tnr,accuracy,precision = test_model(model2, train_data2,  test_data2, tr2)
        if tpr > 0.3 or tnr < 0.5:
            continue
        tpr,tnr,accuracy,precision = test_model(model2, train_data2,  test_data1, tr2)
        if tpr < 0.6 or tnr < 0.5:
            continue
        print("----->",user1,user2)


    exit(1)



    for device_to_test, device_to_train in list(itertools.combinations(ip_list,2)):
        train_data_filename = os.path.join(args['data_cache_dir'], args['train_day'], device_to_train + ".csv")
        test_data_filename = os.path.join(args['data_cache_dir'], args['test_day'], device_to_test + ".csv")

        train_data, _, train_arr = get_data(train_data_filename,start=0, end=5000)
        threshold_data, _, th_arr = get_data(train_data_filename,start=5000, end=8000, batch_size=128)
        test_data, dims, test_arr = get_data(test_data_filename)

        model = AutoEncoder(dims)
        train_model(model, train_data)
        tr = get_local_threshold(model, threshold_data)
        tpr,tnr,accuracy,precision = test_model(model, train_data,  test_data, tr)

        res.append((device_to_test, device_to_train, tpr,tnr,accuracy,precision))
        print("------>",res[-1])

       

    print(res)
    exit(1)
    for device_to_test, device_to_train in list(itertools.combinations(ip_list,2)):

        #device_to_train = '192.168.0.47'
        #device_to_test = '192.168.0.18'
        args = {
            'batch_size' : 10,
            'data_cache_dir' : 'parsed_data',
            'train_day' : '11',
            'test_day' : '12',
            'device_id': 1,
            'test_device': device_to_test,
        }
        
        

        # load data
        #dataset, output_dim = load_data(args,[0])
        dataset, raw, output_dim = load_data(args,[device_to_train])
        model = AutoEncoder(output_dim)
        train_model(model, dataset["train_data"][device_to_train])
        print("----")
        tr = get_local_threshold(model, dataset["benign_th"][device_to_train])
        print(tr)
        print("----")
        tpr,tnr,accuracy,precision = test_model(model, dataset["train_data"][device_to_train],  dataset["test_data"][device_to_train], tr)

        res.append((device_to_test, device_to_train, tpr,tnr,accuracy,precision))
        print(res[-1])
    print(res)



    model = AutoEncoder(115)
    train_model(model, dataset[1][0])
    print("----")
    tr = get_local_threshold(model, dataset[3][0])
    print(tr)
    print("----")
    test_model(model, dataset[1][0], dataset[2][0], tr)

    #print(dataset[1][0])
    # load model
    #model = AutoEncoder(output_dim)