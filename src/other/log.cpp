#include <iostream>
#include <fstream>
using namespace std;

class Log{
public:
    static bool DEBUG;
    static string logFilePath; //TODO: move to global configs

    static fstream logFile;

    template <typename T>
    static void Debug(T var, bool newLine = true, bool save = true){
        if (DEBUG) {
            Write("DEBUG: ", false, save);
            Write(var, newLine, save);
        }
    }

    template <typename T>
    static void Write(T var, bool newLine = true, bool save = true){
        cout << var; //console
        if (save){
            if (!logFile.is_open()) {
                logFile.open(logFilePath, std::ios::app);
            }
            logFile << var;
        }
        if (newLine){
            cout << endl;
            logFile << endl;
        }
    }

    //todo: create write from delegate
    //todo: инкапсуляция DEBUG.
};

bool Log::DEBUG{false};
string logFilePath{"logs.txt"};