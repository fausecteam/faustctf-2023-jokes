FROM faust.cs.fau.de:5000/jokes-deps
COPY service ./
EXPOSE 5000
CMD ["./start.sh"]
