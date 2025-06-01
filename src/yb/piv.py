import subprocess

class Piv:
    """
    Represents operations related to a PIV device functionality.
    """

    @classmethod
    def list_readers(
            cls,
        ) -> list[str]:
        """
        Return a list of connected PIV reader names.
        """

        try:
            out = subprocess.run(
                [
                    'yubico-piv-tool',
                    '--action', 'list-readers'
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to list readers: {e.stderr.strip()}") from e

        readers = []
        for line in out.stdout.splitlines():
            readers.append(line.strip())
        return readers

    @classmethod
    def write_object(
            cls,
            reader: str,
            id: int,
            input: bytes,
        ) -> None:
        """
        Write binary data to a PIV object slot on the device using the specified reader.

        Parameters:
        - reader: The name of the reader to use (as returned by list_readers()).
        - id: The numeric ID of the PIV object (e.g. 0x5fc105 for the certificate slot).
        - input: The binary content to write.

        Raises:
        - RuntimeError: If the command fails or the write operation is unsuccessful.
        """
        
        try:
            subprocess.run(
                [
                    'yubico-piv-tool',
                    '--reader', reader,
                    '--action', 'write-object',
                    '--format', 'binary',
                    '--id', f'{id:#06x}',
                ],
                input=input,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to write object: {e.stderr.decode().strip()}") from e


    @classmethod
    def read_object(
            cls,
            reader: str,
            id: int,
        ) -> bytes:
        """
        Read binary data from a PIV object slot on the device using the specified reader.

        Parameters:
        - reader: The name of the reader to use (as returned by list_readers()).
        - id: The numeric ID of the PIV object (e.g. 0x5fc105 for the certificate slot).

        Returns:
        - The binary content read from the PIV object.

        Raises:
        - RuntimeError: If the command fails or the read operation is unsuccessful.
        """
        try:
            out = subprocess.run(
                [
                    'yubico-piv-tool',
                    '--reader', reader,
                    '--action', 'read-object',
                    '--format', 'binary',
                    '--id', f'{id:#06x}',
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return out.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to read object: {e.stderr.decode().strip()}") from e
        
    @classmethod
    def verify_reader(
            cls,
            reader: str,
            id: int,
        ) -> bool:
        ''''''
        try:
            with open("/dev/null", "rb") as devnull:
                subprocess.run(
                    [
                        'yubico-piv-tool',
                        '--reader', reader,
                        '--action', 'verify-pin',
                        '--id', f'{id:#06x}',
                    ],
                    stdin=devnull,
                    capture_output=True,
                    text=True,
                    check=True,
                )
        except subprocess.CalledProcessError:
            return False
        return True
