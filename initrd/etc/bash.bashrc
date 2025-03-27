# /etc/bash.bashrc

# Enable command history
HISTFILE=~/.bash_history
HISTSIZE=1000

# Enable command completion
if [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi

# Set default editor
export EDITOR=vi

# Set default pager
export PAGER=less

# Set default umask
umask 022

# Set default locale
export LANG=C
export LC_ALL=C 