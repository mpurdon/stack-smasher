# StackSmasher

StackSmasher is a Python command-line tool that helps you recursively delete all resources in an AWS CloudFormation stack that failed to delete.

## Features

- List all CloudFormation stacks in `DELETE_FAILED` state.
- Select a stack to delete.
- Display resources in the selected stack in a table.

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/yourusername/stack-smasher.git
   cd stack-smasher
   ```

2. Install Poetry (if not already installed):

```sh
curl -sSL https://install.python-poetry.org | python3 -
```

3. Install the dependencies:

```sh
poetry install
```

## Usage

1. Ensure you have AWS credentials configured. You can set them up using `aws configure`.

2. Run StackSmasher:

   ```sh
   poetry run python smasher.py
   ```

3. Follow the prompts to select and delete a stack.

## Development

### Code Formatting

This project uses `black` for code formatting. To format the code, run:

```sh
black .
```

## Contributing

Contributions are not welcome! Just fork it and don't bug me.

## License

This project is licensed under the MIT License.
