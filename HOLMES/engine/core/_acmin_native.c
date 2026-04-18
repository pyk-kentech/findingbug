#define PY_SSIZE_T_CLEAN
#include <Python.h>

#ifdef _OPENMP
#include <omp.h>
#endif

typedef struct {
    Py_ssize_t *data;
    Py_ssize_t size;
    Py_ssize_t cap;
} index_vec_t;

static int vec_init(index_vec_t *v, Py_ssize_t cap_hint) {
    if (cap_hint < 16) {
        cap_hint = 16;
    }
    v->data = (Py_ssize_t *)PyMem_Malloc((size_t)cap_hint * sizeof(Py_ssize_t));
    if (v->data == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    v->size = 0;
    v->cap = cap_hint;
    return 0;
}

static int vec_push(index_vec_t *v, Py_ssize_t x) {
    if (v->size >= v->cap) {
        Py_ssize_t new_cap = v->cap * 2;
        Py_ssize_t *new_data = (Py_ssize_t *)PyMem_Realloc(v->data, (size_t)new_cap * sizeof(Py_ssize_t));
        if (new_data == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        v->data = new_data;
        v->cap = new_cap;
    }
    v->data[v->size++] = x;
    return 0;
}

static void vec_free(index_vec_t *v) {
    if (v->data != NULL) {
        PyMem_Free(v->data);
    }
    v->data = NULL;
    v->size = 0;
    v->cap = 0;
}

static PyObject *ac_min_setdiff(PyObject *self, PyObject *args) {
    PyObject *common = NULL;
    PyObject *ancestors_by_node = NULL;
    if (!PyArg_ParseTuple(args, "OO", &common, &ancestors_by_node)) {
        return NULL;
    }
    if (!PyAnySet_Check(common)) {
        PyErr_SetString(PyExc_TypeError, "common must be a set or frozenset");
        return NULL;
    }
    if (!PyDict_Check(ancestors_by_node)) {
        PyErr_SetString(PyExc_TypeError, "ancestors_by_node must be a dict");
        return NULL;
    }

    PyObject *common_list = PySequence_List(common);
    if (common_list == NULL) {
        return NULL;
    }
    Py_ssize_t n = PyList_GET_SIZE(common_list);

    PyObject *idx_by_node = PyDict_New();
    if (idx_by_node == NULL) {
        Py_DECREF(common_list);
        return NULL;
    }

    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *node = PyList_GET_ITEM(common_list, i);  // borrowed
        PyObject *idx_obj = PyLong_FromSsize_t(i);
        if (idx_obj == NULL) {
            Py_DECREF(idx_by_node);
            Py_DECREF(common_list);
            return NULL;
        }
        if (PyDict_SetItem(idx_by_node, node, idx_obj) < 0) {
            Py_DECREF(idx_obj);
            Py_DECREF(idx_by_node);
            Py_DECREF(common_list);
            return NULL;
        }
        Py_DECREF(idx_obj);
    }

    Py_ssize_t *offsets = (Py_ssize_t *)PyMem_Malloc((size_t)(n + 1) * sizeof(Py_ssize_t));
    if (offsets == NULL) {
        PyErr_NoMemory();
        Py_DECREF(idx_by_node);
        Py_DECREF(common_list);
        return NULL;
    }

    index_vec_t flat;
    if (vec_init(&flat, n * 4) < 0) {
        PyMem_Free(offsets);
        Py_DECREF(idx_by_node);
        Py_DECREF(common_list);
        return NULL;
    }

    for (Py_ssize_t i = 0; i < n; i++) {
        offsets[i] = flat.size;
        PyObject *b = PyList_GET_ITEM(common_list, i);  // borrowed
        PyObject *ancestors = PyDict_GetItemWithError(ancestors_by_node, b);  // borrowed
        if (ancestors == NULL) {
            if (PyErr_Occurred()) {
                vec_free(&flat);
                PyMem_Free(offsets);
                Py_DECREF(idx_by_node);
                Py_DECREF(common_list);
                return NULL;
            }
            continue;
        }

        PyObject *it = PyObject_GetIter(ancestors);
        if (it == NULL) {
            vec_free(&flat);
            PyMem_Free(offsets);
            Py_DECREF(idx_by_node);
            Py_DECREF(common_list);
            return NULL;
        }
        PyObject *a = NULL;
        while ((a = PyIter_Next(it)) != NULL) {
            int eq = PyObject_RichCompareBool(a, b, Py_EQ);
            if (eq < 0) {
                Py_DECREF(a);
                Py_DECREF(it);
                vec_free(&flat);
                PyMem_Free(offsets);
                Py_DECREF(idx_by_node);
                Py_DECREF(common_list);
                return NULL;
            }
            if (eq == 0) {
                PyObject *idx_obj = PyDict_GetItemWithError(idx_by_node, a);  // borrowed
                if (idx_obj == NULL) {
                    if (PyErr_Occurred()) {
                        Py_DECREF(a);
                        Py_DECREF(it);
                        vec_free(&flat);
                        PyMem_Free(offsets);
                        Py_DECREF(idx_by_node);
                        Py_DECREF(common_list);
                        return NULL;
                    }
                } else {
                    Py_ssize_t idx = PyLong_AsSsize_t(idx_obj);
                    if (idx == -1 && PyErr_Occurred()) {
                        Py_DECREF(a);
                        Py_DECREF(it);
                        vec_free(&flat);
                        PyMem_Free(offsets);
                        Py_DECREF(idx_by_node);
                        Py_DECREF(common_list);
                        return NULL;
                    }
                    if (vec_push(&flat, idx) < 0) {
                        Py_DECREF(a);
                        Py_DECREF(it);
                        vec_free(&flat);
                        PyMem_Free(offsets);
                        Py_DECREF(idx_by_node);
                        Py_DECREF(common_list);
                        return NULL;
                    }
                }
            }
            Py_DECREF(a);
        }
        Py_DECREF(it);
        if (PyErr_Occurred()) {
            vec_free(&flat);
            PyMem_Free(offsets);
            Py_DECREF(idx_by_node);
            Py_DECREF(common_list);
            return NULL;
        }
    }
    offsets[n] = flat.size;

    unsigned char *removed = (unsigned char *)PyMem_Calloc((size_t)n, sizeof(unsigned char));
    if (removed == NULL) {
        PyErr_NoMemory();
        vec_free(&flat);
        PyMem_Free(offsets);
        Py_DECREF(idx_by_node);
        Py_DECREF(common_list);
        return NULL;
    }

    Py_ssize_t m = flat.size;
#ifdef _OPENMP
    Py_BEGIN_ALLOW_THREADS
#pragma omp parallel for schedule(static)
    for (Py_ssize_t k = 0; k < m; k++) {
        Py_ssize_t idx = flat.data[k];
        if (idx >= 0 && idx < n) {
#pragma omp atomic write
            removed[idx] = 1;
        }
    }
    Py_END_ALLOW_THREADS
#else
    for (Py_ssize_t k = 0; k < m; k++) {
        Py_ssize_t idx = flat.data[k];
        if (idx >= 0 && idx < n) {
            removed[idx] = 1;
        }
    }
#endif

    PyObject *result = PySet_New(NULL);
    if (result == NULL) {
        PyMem_Free(removed);
        vec_free(&flat);
        PyMem_Free(offsets);
        Py_DECREF(idx_by_node);
        Py_DECREF(common_list);
        return NULL;
    }

    for (Py_ssize_t i = 0; i < n; i++) {
        if (removed[i] == 0) {
            PyObject *node = PyList_GET_ITEM(common_list, i);  // borrowed
            if (PySet_Add(result, node) < 0) {
                Py_DECREF(result);
                PyMem_Free(removed);
                vec_free(&flat);
                PyMem_Free(offsets);
                Py_DECREF(idx_by_node);
                Py_DECREF(common_list);
                return NULL;
            }
        }
    }

    PyMem_Free(removed);
    vec_free(&flat);
    PyMem_Free(offsets);
    Py_DECREF(idx_by_node);
    Py_DECREF(common_list);
    return result;
}

static PyMethodDef ModuleMethods[] = {
    {"ac_min_setdiff", ac_min_setdiff, METH_VARARGS, "Compute AC_min via set-difference in C."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_acmin_native",
    "Native accelerators for AC_min.",
    -1,
    ModuleMethods
};

PyMODINIT_FUNC PyInit__acmin_native(void) {
    return PyModule_Create(&moduledef);
}
