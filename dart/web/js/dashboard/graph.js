// var data=[{"countryName": "China", "count": 5}, {"countryName": "Russia", "count": 4}, {"countryName": "United States", "count": 3}, {"countryName": "Germany", "count": 1}, {"countryName": "Iceland", "count": 1}, {"countryName": "Seychelles", "count": 1}];

var svg ;

var g;
// DRAWING

function draw(id) {

    var bounds = svg.node().getBoundingClientRect(),
        width = bounds.width - margin.left - margin.right,
        height = bounds.height - margin.top - margin.bottom;

    x.rangeRound([0, width]);
    y.rangeRound([height, 0]);

    var color = d3.scaleOrdinal().range(["#16A085","#27AE60","#2980B9","#8E44AD","#F39C12","#D35400","#C0392B","#1ABC9C","#2ECC71","#3498DB","#9B59B6","#34495E",
        "#F1C40F","#E67E22","#E74C3C","#ECF0F1","#95A5A6","#BDC3C7","#7F8C8D"]);

    g.select(".axis--x")
        .attr("transform", "translate(0," + height + ")")
        .call(d3.axisBottom(x))
        .selectAll('text')
        .attr("transform", "rotate(-65)")
        .attr("y", 6)
        .attr("dy", "0.71em")
        .attr("text-anchor", "end");




    var bars = g.selectAll(".bar")
        .data(theData);

    if(id === 'barchart'){
        g.select(".axis--y")
            .call(d3.axisLeft(y).ticks(10, ""));
        // ENTER
        bars
            .enter().append("rect")
            .on("click", changecenter)
            .attr('fill', (d,i) => color(i))
            .attr("x", function (d) { return x(d.countryName); })
            .attr("y", function (d) { return y(d.count); })
            .attr("width", x.bandwidth())
            .attr("height", function (d) { return height - y(d.count); })
            .append("title")
            .text(function (d) {
                return d.countryName+' '+d.count;
            });

        // UPDATE
        bars.attr("x", function (d) { return x(d.countryName); })
            .attr("y", function (d) { return y(d.count); })
            .attr("width", x.bandwidth())
            .attr("height", function (d) { return height - y(d.count); });
    }
    else if(id === 'barchart_time'){
        g.select(".axis--y")
            .call(d3.axisLeft(y).ticks(10, "").tickFormat(d3.format("d")));
        // ENTER
        bars
            .enter().append("rect")
            .on("click", changecenter)
            .attr('fill', (d,i) => color(i))
            .attr("x", function (d) { return x(d.Month); })
            .attr("y", function (d) { return y(d.Count); })
            .attr("width", x.bandwidth())
            .attr("height", function (d) { return height - y(d.Count); })
            .append("title")
            .text(function (d) {
                return d.Month+' '+d.Count;
            });

        // UPDATE
        bars.attr("x", function (d) { return x(d.Month); })
            .attr("y", function (d) { return y(d.Count); })
            .attr("width", x.bandwidth())
            .attr("height", function (d) { return height - y(d.Count); });
    }




    // EXIT
    bars.exit()
        .remove();

}

// LOADING DATA

function createCountryBarChart(data,id) {
    // SETUP
    svg=null;
   svg = d3.select("#"+id),
        margin = { top: 20, right: 20, bottom: 60, left: 80 },
        x = d3.scaleBand().padding(0.1),
        y = d3.scaleLinear(),
        theData = data;

    g = svg.append("g")
        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    g.append("g")
        .attr("class", "axis axis--x");

    g.append("g")
        .attr("class", "axis axis--y");

    g.append("text")
        .attr("transform", "rotate(-90)")
        .attr("y", 0 - margin.left)
        .attr("x", -100)
        .attr("dy", "0.71em")
        .attr("text-anchor", "end")
        .text("count");

        x.domain(theData.map(function (d) {
            if(id === 'barchart'){
                return d.countryName;
            }
            else if(id === 'barchart_time'){
                return d.Month;
            }
        }));
        y.domain([0, d3.max(theData, function (d) {
            if(id === 'barchart'){
                return d.count;
            }
            else if(id === 'barchart_time'){
                return d.Count;
            }
        })]);

        draw(id);

}




// START!

window.addEventListener("resize", draw);