"""Entry-point module for ryu-manager.

The concrete controller implementation lives in the `controller` package.
"""

from controller.app import IoTACLTokenController

__all__ = ["IoTACLTokenController"]
