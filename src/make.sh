
dirs='server agent admin'
for subdir in $dirs; do
  echo "directory $subdir:"
  cd $subdir && make $1
  cd ..
  echo
done
