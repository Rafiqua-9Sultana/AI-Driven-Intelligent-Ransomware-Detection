import shutil
import time
from pathlib import Path


SIMULATION_DIR = Path(__file__).resolve().parent
DETECTION_ENGINE_DIR = SIMULATION_DIR.parent

DEMO_FOLDER = DETECTION_ENGINE_DIR / "demo_folder"

NORMAL_FOLDER = (
    DEMO_FOLDER / "normal_simulation"
)

TOTAL_CYCLES = 30

WAIT_BETWEEN_CYCLES = 16


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
        NORMAL_FOLDER
    )

    if NORMAL_FOLDER.exists():

        shutil.rmtree(
            NORMAL_FOLDER
        )

    NORMAL_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )


def simulate_normal_activity():

    prepare_folder()

    print(
        "Normal activity simulation started."
    )

    print(
        "Working folder:",
        NORMAL_FOLDER
    )

    print(
        "Keep collect_data.py running "
        "in another terminal.\n"
    )

    for cycle in range(
        1,
        TOTAL_CYCLES + 1
    ):

        file_path = (
            NORMAL_FOLDER
            / f"document_{cycle}.txt"
        )

        normal_text = (
            f"This is normal document "
            f"number {cycle}.\n"
            "The user is creating and "
            "editing an ordinary text file.\n"
            "No suspicious encryption "
            "activity is occurring.\n"
        )

        file_path.write_text(
            normal_text,
            encoding="utf-8"
        )

        print(
            f"[Cycle {cycle}] "
            f"Created: {file_path.name}"
        )

        time.sleep(1)

        with file_path.open(
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                "Additional normal "
                "content was saved.\n"
            )

        print(
            f"[Cycle {cycle}] "
            f"Modified: {file_path.name}"
        )

        time.sleep(1)

        copied_file = (
            NORMAL_FOLDER
            / f"document_{cycle}_copy.txt"
        )

        shutil.copy2(
            file_path,
            copied_file
        )

        print(
            f"[Cycle {cycle}] "
            f"Copied: {copied_file.name}"
        )

        if cycle % 3 == 0:

            renamed_file = (
                NORMAL_FOLDER
                / f"notes_{cycle}.txt"
            )

            copied_file.rename(
                renamed_file
            )

            print(
                f"[Cycle {cycle}] "
                f"Renamed once: "
                f"{copied_file.name} "
                f"-> {renamed_file.name}"
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
        "\nNormal simulation completed."
    )


if __name__ == "__main__":

    try:

        simulate_normal_activity()

    except KeyboardInterrupt:

        print(
            "\nNormal simulation stopped."
        )

    except Exception as error:

        print(
            f"\nSimulation failed: {error}"
        )