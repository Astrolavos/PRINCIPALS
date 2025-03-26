import fedml
from data.data_loader import load_data
from fedml import FedMLRunner
from model.autoencoder import AutoEncoder
from trainer.fed_detect_aggregator import FedDetectAggregator
from trainer.fed_detect_trainer import FedDetectTrainer

def get_data(args):
    return load_data(args)

if __name__ == "__main__":
    # init FedML framework
    args = fedml.init()
    print(f"batch is {args.batch_size}")
    exit(1)

    # init device
    device = fedml.device.get_device(args)
    print(f"device is {device}")

    # load data
    dataset, output_dim = load_data(args)
    # load model
    model = AutoEncoder(output_dim)

    # create trainer
    trainer = FedDetectTrainer(model, args)
    aggregator = FedDetectAggregator(model, args)

    # start training
    fedml_runner = FedMLRunner(args, device, dataset, model, trainer, aggregator)
    fedml_runner.run()

    print(trainer.get_model_params())
    
