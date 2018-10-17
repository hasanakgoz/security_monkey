function createPieChart(data){
    var text = "";

    var width = 400;
    var height = 400;
    var thickness = 40;
    var duration = 750;
    var padding = 50;
    var opacity = .8;
    var opacityHover = 1;
    var otherOpacityOnHover = .8;
    var tooltipMargin = 13;

    var radius = Math.min(width-padding, height-padding) / 2;
    var color = d3.scaleOrdinal(["#16A085","#27AE60","#2980B9","#8E44AD","#F39C12","#D35400","#C0392B","#1ABC9C","#2ECC71","#3498DB","#9B59B6","#34495E",
    "#F1C40F","#E67E22","#E74C3C","#ECF0F1","#95A5A6","#BDC3C7","#7F8C8D"]);

    var svg = d3.select("#piechart")
        .append('svg')
        .attr('class', 'pie')
        .attr('width', width)
        .attr('height', height);

    var g = svg.append('g')
        .attr('transform', 'translate(' + (width/2) + ',' + (height/2) + ')');

    var arc = d3.arc()
        .innerRadius(0)
        .outerRadius(radius);

    var pie = d3.pie()
        .value(function(d) { return d.percentage; })
        .sort(null);

    var path = g.selectAll('path')
        .data(pie(data))
        .enter()
        .append("g")
        .append('path')
        .attr('d', arc)
        .attr('fill', (d,i) => color(i))
        .style('opacity', opacity)
        .style('stroke', 'white')
        .on("mouseover", function(d) {
            d3.selectAll('path')
                .style("opacity", otherOpacityOnHover);
            d3.select(this)
                .style("opacity", opacityHover);

            let g = d3.select("svg")
                .style("cursor", "pointer")
                .append("g")
                .attr("class", "tooltip")
                .style("opacity", 0);

            g.append("text")
                .attr("class", "name-text")
                .text(`${d.data.name} (${d.data.value})`)
                .attr('text-anchor', 'middle');

            let text = g.select("text");
            let bbox = text.node().getBBox();
            let padding = 2;
            g.insert("rect", "text")
                .attr("x", bbox.x - padding)
                .attr("y", bbox.y - padding)
                .attr("width", bbox.width + (padding*2))
                .attr("height", bbox.height + (padding*2))
                .style("fill", "white")
                .style("opacity", 0.75);
        })
        .on("click",filterByTech)
        .append("title")
        .text(function(d){
            return d.data.technology+' '+d.data.count+' - '+d.data.percentage+'%: '+d.data.percentage;
        })

        .each(function(d, i) { this._current = i; });
}