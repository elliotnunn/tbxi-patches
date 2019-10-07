# Library of scripts that patch the Mac OS ROM

These patches depend on the `tbxi` library. Install and use it like this:

	python3 -m pip install tbxi # Toolbox Imager: https://pypi.org/project/tbxi/
	
	git clone https://github.com/elliotnunn/tbxi-patches.git
	
	tbxi-patches/macmini.py /path/to/MacOSROM -o ~/mac-mini-rom.hqx


## Useful scripts

Included are the simple PowerPC assembler `ppcasm.py` and the Preferred
Executable Format manipulator `cfmtool.py`. Feel free to include them in your
own projects.
