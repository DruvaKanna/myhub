# SimuWorld — Engineering Simulation Studio

## Run the app
1. Download or clone the repository.
2. Open the `SimuWorld` folder.
3. Open `index.html` in Chrome or Edge.

No installation, server, account, or API key is required for this standalone prototype.

## Included in this build
- Searchable component catalog spanning conveyors, gears, motors, power transmission, bearings, hydraulics, pneumatics, sensors, electrical parts, robotics, manufacturing, and structural components.
- Category filters, specification search, component inspector, and custom component creation.
- Assembly workspace with component placement, dragging, positioning, rotation, connection lines, and basic interface compatibility checks.
- Starter educational simulations for gear transmission, conveyor drive, and motor power estimates.
- Project save to browser storage, JSON project export, and JSON component-library import.
- Engineering guide with introductory component explanations.

## Important data and simulation notes
The built-in catalog contains illustrative reference profiles and example values. They are not verified manufacturer specifications. Manufacturer names, model numbers, and datasheet claims are not fabricated. Use original manufacturer datasheets to confirm real-world dimensions, ratings, materials, and operating limits before selecting physical components.

The simulations are simplified educational models:
- Gear transmission uses an idealized gear ratio and efficiency estimate.
- Conveyor drive estimates belt speed from pulley diameter and rotational speed; its power estimate uses an illustrative resistance assumption.
- Motor performance estimates output power and torque from user-entered voltage, current, efficiency, and speed.

The current build does not perform detailed 3D finite-element analysis, tooth-contact analysis, belt tension calculations, shaft or bearing life analysis, thermal analysis, safety validation, PLC execution, or full multi-body physics. Connection checks use simplified interface labels. It is not suitable for certifying, validating, or approving a physical machine design.

## Local storage
Saved projects stay in the browser profile on the device where they were created. There are no cloud accounts or cross-device synchronization in this prototype. Export important work as a JSON file for backup.
