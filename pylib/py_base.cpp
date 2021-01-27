#include "py_base.h"
#include "other.h"
#include "Python.h"


namespace c2pool::python
{
    bool Py::_ready = false;

    void Py::Initialize()
    {
        if (!_ready)
        {
            Py_Initialize();
            _ready = true;
        }
    }

    void Py::Finalize()
    {
        if (_ready)
        {
            Py_Finalize();
            _ready = false;
        }
    }
} // namespace c2pool::python
