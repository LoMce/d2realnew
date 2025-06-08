#ifndef DRAWING_H
#define DRAWING_H

#include "pch.h"


class Drawing
{
private:
	static LPCSTR lpWindowName;
	static ImVec2 vWindowSize;
	static ImGuiWindowFlags WindowFlags;
	static bool bDraw;

	// fonts here
	static ImFont* headerText;
	static ImFont* xButtonFont;
	static ImFont* bigTimeFont;
	static ImFont* bigTimeFontFira;
public:
	static void Active();
	static bool isActive();
	static void Draw();
	static void Poll();
};

#endif
