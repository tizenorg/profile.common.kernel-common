#!/bin/bash
# author: me
#---------------------------------------------------------------------
# A. SUMMARY (see instructions below)
#---------------------------------------------------------------------
# 
# This script is intended to help you to
#
#  UPDATE THE DEFCONFIG FILES AFTER BUMPING KERNEL VERSION
#
# This is needed because the configurations are kept using
# the delta to the default configuration of the kernel.
#
# Here is the detailed explaination based on the figure below:
#
#      KERNEL A                    KERNEL B
#
#      default A ------[1]-------> default B
#         |                           |
#         | defA                 defB |
#         v                           v
#       tizen A -------[2]------->  tizen B
#
# When bumping from the kernel A to the kernel B, the default
# configuration files of the kernels are changing from "default A"
# to "default B". That changes are figured by the transition [1].
#
# The tizen configuration ("tizen A" and "tizen B") may also 
# change but it is generally conservative and change only few. 
# This possible changes are figured by the transition [2].
#
# The configurations of tizen are in fact stored as the defconfig
# files "defA" and "defB". This files are keeping the differences
# between the default configuration of the kernel and the effective
# configuration of tizen. The transition from "default A" to "tizen A"
# is figured by "defA" that is also a file. The same applies for B.
#
# When bumping the kernel from version A to version B, defconfig
# files has to be changed from "defA" to "defB" in a such way that:
#
#  defB o [1] = [2] o defA     or      defB([1]) = [2](defA)
#
# This script suppose that [2] = identity and helps to compute
# defbB such that defB([1])=defA.
# 
#---------------------------------------------------------------------
# B. INSTRUCTIONS
#---------------------------------------------------------------------
#
# 1. FIRST, that script updates the defconfigs for the following
# architectures:
# 
ARCHITECTURES="x86 x86_64 arm"
#
# 2. SECOND, you must set the HEAD of your kernel git to the bumped 
# version where you want to update the defconfig files.
# 
# For example, imagine that you bumped to the version B of the
# kernel and cherry-picked the packaging files of the previous
# version. Then you are in the good state to run script.
# 
# Check that this list is correct and update it if needed.
#
# 3. THIRD, call that script with as only argument the commit
# (SHA, branch, tag) of the previous version that you want to
# import in the current place.
#
#--------------------------------------------------------------------
#
# create a pattern name for temporarily files
#
preftmp="/tmp/$(basename $0)-$$-"
#
# Convenient function for handling errors
#
here=
error() {
  echo "error: $*" >&2
  [ -n "$here" ] && git checkout -f "$origin"
  rm ${preftmp}* 2>/dev/null
  exit 1
}
#
[ "$#" = "1" ] || error "expected argument not found"
origin="$1"
#
# This script requires the git command.
#
[ -n "$(which git)" ] || error "command 'git' not found"
#
# Check that the current state is clean
#
[ -z "$(git status --short)" ] || error "local changes found, please stash/clean"
#
# Record the current HEAD branch and check that it is not changed
#
set -- $(git status --short --branch --porcelain)
[ "$1" = "##" ] || error "unrecognized output for 'git status'"
[ "$#" = "2" ] || error "status not clean: $*"
[ "$2" != "HEAD" ] || error "you must be on a branch"
here="$2"
echo "starting from clean branch $here"
#
# get the root of kernel's git
#
root="$(git rev-parse --show-toplevel)"
#
# this variables are globals
#
cfgpath=   ; # path for the def config
arch=      ; # arch name
platform=  ; # platform name
defcnf=    ; # defconfig basename
#
# this function set the global variables
#
setvars() {
  case "$1" in 
    i386|i486|i586|i686|x86)
      cfgpath=arch/x86/configs
      arch=i386
      platform=i386
      ;;
    x86_64)
      cfgpath=arch/x86/configs
      arch=x86_64
      platform=x86_64
      ;;
    arm|vexpress)
      cfgpath=arch/arm/configs
      arch=arm
      platform=vexpress
      ;;
    *)
      error "Unknown arch '$1'"
      ;;
  esac
  defcnf=${platform}_defconfig
}
#
# check the given origin
#
[ -n "$(git show --pretty=format:%H --no-patch "$origin")" ] || error "commit $origin not found"
#
# Restore the given origin
#
git checkout "$origin" || error "can't switch to $origin"
cd "$root"
#
# create the config files from the original defconfigs
# and save it in the temporary storage files
#
for a in $ARCHITECTURES
do
  setvars "$a"
  rm -f .config
  #
  # compute the config from the defconfig stored
  #
  make "ARCH=$arch" "$defcnf" || error "can not create config from $defcnf"
  #
  # save it temporarily
  #
  mv .config "$preftmp-config.$a" || error "can't move .config to $preftmp-config.$a"
done
#
# Restore the commit to update
#
git checkout -f "$here" || error "can't switch to $here"
cd "$root"
#
# update the defconfig files using the computed config files
#
for a in $ARCHITECTURES
do
  setvars "$a"
  #
  # restore the previously computed config
  #
  mv "$preftmp-config.$a" .config || error "can't move $preftmp-config.$a to .config"
  #
  # NOTE: the step:
  #     make "ARCH=$arch" oldconfig || error "can not create config from $defcnf"
  # is not needed because it is of neutral effect
  #
  # create the defconfig from the restored config config
  # 
  make "ARCH=$arch" savedefconfig || error "can't produce the defconfig file"
  #
  # save now the computed defconfig
  #
  mv defconfig "$cfgpath/$defcnf" || error "can't move defconfig to $cfgpath/$defcnf"
  rm -f .config
done
#
# end
#
