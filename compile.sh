targetdir=target

if [ ! -d "$targetdir" ]; then mkdir $targetdir; fi

javac -sourcepath src -d $targetdir -cp lib/ECLA.jar:lib/DTNConsoleConnection.jar:lib/bcprov-jdk18on-1.80.jar src/core/*.java src/movement/*.java src/report/*.java src/routing/*.java src/gui/*.java src/input/*.java src/applications/*.java src/interfaces/*.java

if [ ! -d "$targetdir/gui/buttonGraphics" ]; then cp -R src/gui/buttonGraphics target/gui/; fi
