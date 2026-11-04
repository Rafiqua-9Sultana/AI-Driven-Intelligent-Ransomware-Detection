import os
import shutil
import time
from pathlib import Path


SIMULATION_DIR = Path(__file__).resolve().parent
DETECTION_ENGINE_DIR = SIMULATION_DIR.parent

DEMO_FOLDER = DETECTION_ENGINE_DIR / "demo_folder"

RANSOMWARE_FOLDER = (
    DEMO_FOLDER
    / "ransomware_simulation"
)

TOTAL_CYCLES = 30

FILES_PER_CYCLE = 5

WAIT_BETWEEN_CYCLES = 16

RANDOM_DATA_SIZE = 4096


def verify_safe_path(folder):

    demo_path = DEMO_FOLDER.resolve()
    target_path = folder.resolve()

    if (
        demo_path not in target_path.parents
        and target_path != demo_path
    ):
        raise RuntimeError(
            "Unsafe path detected. "
            "Simulation stopped."
        )


def prepare_folder():

    verify_safe_path(
        RANSOMWARE_FOLDER
    )

    if RANSOMWARE_FOLDER.exists():

        shutil.rmtree(
            RANSOMWARE_FOLDER
        )

    RANSOMWARE_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )


def simulate_ransomware_activity():

    prepare_folder()

    print(
        "Safe ransomware-like simulation started."
    )

    print(
        "Working folder:",
        RANSOMWARE_FOLDER
    )

    print(
        "Only files inside "
        "demo_folder are affected."
    )

    print(
        "Keep collect_data.py running "
        "in another terminal.\n"
    )

    for cycle in range(
        1,
        TOTAL_CYCLES + 1
    ):

        created_files = []

        # ------------------------------------------
        # CREATE FILES
        # ------------------------------------------

        for file_number in range(
            1,
            FILES_PER_CYCLE + 1
        ):

            file_path = (
                RANSOMWARE_FOLDER
                / f"sample_{cycle}_{file_number}.txt"
            )

            file_path.write_text(
                "Disposable test file "
                "for controlled simulation.\n",
                encoding="utf-8"
            )

            created_files.append(
                file_path
            )

        print(
            f"[Cycle {cycle}] "
            f"Created "
            f"{len(created_files)} "
            f"disposable files."
        )

        time.sleep(1)

        # ------------------------------------------
        # HIGH-ENTROPY TEST DATA
        # ------------------------------------------

        for file_path in created_files:

            file_path.write_bytes(
                os.urandom(
                    RANDOM_DATA_SIZE
                )
            )

        print(
            f"[Cycle {cycle}] "
            "Generated high-entropy "
            "test data."
        )

        time.sleep(1)

        # ------------------------------------------
        # RENAME TO .LOCKED
        # ------------------------------------------

        for file_path in created_files:

            locked_path = (
                file_path.with_suffix(
                    file_path.suffix
                    + ".locked"
                )
            )

            file_path.rename(
                locked_path
            )

        print(
            f"[Cycle {cycle}] "
            f"Rapidly renamed "
            f"{len(created_files)} "
            f"files to .locked."
        )

        print(
            f"[Cycle {cycle}] "
            f"Waiting "
            f"{WAIT_BETWEEN_CYCLES} seconds..."
        )

        time.sleep(
            WAIT_BETWEEN_CYCLES
        )

    print(
        "\nRansomware-like "
        "simulation completed safely."
    )


if __name__ == "__main__":

    try:

        simulate_ransomware_activity()

    except KeyboardInterrupt:

        print(
            "\nRansomware simulation stopped."
        )

    except Exception as error:

        print(
            f"\nSimulation failed: {error}"
        )