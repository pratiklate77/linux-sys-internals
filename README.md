Linux System Internals

A Linux system internals toolkit written in Python, designed to explore and monitor
low-level system components such as disks, CPU, memory, and processes.

IMPORTANT:
All functionality in this project runs strictly through main.py.
Individual tool files are NOT standalone and must not be executed directly.


PROJECT OVERVIEW

This project follows a single-entry, controller-based architecture:

- main.py is the only executable file
- All system tools are modules controlled by main.py
- Tools share state, configuration, and execution flow

This design provides centralized control, clean modular structure,
and easier future expansion.


PROJECT STRUCTURE

linux-sys-internals/
├── main.py              (Main entry point - mandatory)
├── disk_tool.py         (Disk monitoring module)
├── cpu_tool.py          (CPU monitoring module)
├── memory_tool.py       (Memory statistics module)
├── process_tool.py      (Process monitoring module)

Do NOT run tool files directly.
Always run main.py.


HOW TO RUN (ONLY SUPPORTED WAY)

python main.py
or
python3 main.py

This initializes the system environment, loads all tools,
and manages execution and output.


UNSUPPORTED USAGE (WILL NOT WORK)

python disk_tool.py
python cpu_tool.py

These files depend on initialization done in main.py and
are designed as internal modules only.


WHY THIS DESIGN?

Each tool depends on shared state created by main.py and uses
centralized execution logic. The tools are modules, not
independent programs.

This architecture is similar to plugin-based systems and
controller–worker models.


LEARNING OUTCOMES

- Understanding Linux system internals
- Disk, CPU, memory, and process monitoring concepts
- Modular Python application design
- Centralized execution flow
- Real-world system programming patterns


FUTURE IMPROVEMENTS

- Tool enable/disable options from main program
- CLI arguments for selective execution
- Logging and data export
- GUI-based frontend
- Plugin auto-discovery mechanism


AUTHOR

Pratik Late
Linux System Internals | Python Systems Programming


RESUME DESCRIPTION

Built a centralized Linux system internals monitoring toolkit in Python
using a single-entry execution model where all subsystem tools are
managed and coordinated through a main controller program.
