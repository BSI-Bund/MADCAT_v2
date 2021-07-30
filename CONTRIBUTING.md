## Styleguides

### Git Commit Messages

* Limit the first line to 72 characters or less.
* Reference issues and pull requests after the first line.


## Coding Convetions

* Indent using four spaces
* Always put spaces after list items and parameters
* Stick to the below conventions as close as possible

### C Code

C Coding Style is Kernighan & Ritchie style:

```
int foo(int ibar, double dbar)
{
    if (ibar > 5 && dbar == 3) {
        foobar(ibar + dbar);
        return 1;
    } else
        return 0;
}
```

You may use an autoformater like [astyle](http://astyle.sourceforge.net/):

```
astyle --style=kr File [...]
```

### Python Code

Python Coding Style is [PEP 8](https://www.python.org/dev/peps/pep-0008/).

If you decide to use an autoformater like [autopep8](https://pypi.org/project/autopep8/):

```
autopep8 --in-place --aggressive --aggressive File [...]
```

# Thanks a lot!