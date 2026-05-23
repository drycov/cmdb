/**
 * Frontend module for components TopologyGraph.
 */
import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import type { TopologyGraphEdgeResponse, TopologyGraphNodeResponse } from "../types/api";

interface TopologyGraphProps {
  nodes: TopologyGraphNodeResponse[];
  edges: TopologyGraphEdgeResponse[];
}

function TopologyGraph({ nodes, edges }: TopologyGraphProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!containerRef.current) {
      return;
    }

    const elements = [
      ...nodes.map((node) => ({
        data: {
          id: node.device_id,
          label: node.identity,
          role: node.role,
          vendor: node.vendor,
        },
      })),
      ...edges.map((edge) => ({
        data: {
          id: edge.link_id,
          source: edge.source_device_id,
          target: edge.target_device_id,
          label: `${edge.source_interface} → ${edge.target_interface ?? "?"}`,
          confidence: edge.confidence,
          layer: edge.layer,
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#2563eb",
            label: "data(label)",
            color: "#ffffff",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": "12px",
            "text-outline-color": "#1d4ed8",
            "text-outline-width": 2,
            width: 56,
            height: 56,
            "overlay-padding": "8px",
          },
        },
        {
          selector: 'node[role *= "core"]',
          style: {
            "background-color": "#d97706",
            "text-outline-color": "#b45309",
          },
        },
        {
          selector: 'node[role *= "access"], node[role *= "edge"]',
          style: {
            "background-color": "#0f766e",
            "text-outline-color": "#115e59",
          },
        },
        {
          selector: "edge",
          style: {
            width: "mapData(confidence, 0, 1, 2, 6)",
            "line-color": "#8fb8ff",
            "target-arrow-color": "#8fb8ff",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "label": "data(label)",
            "font-size": 10,
            "text-rotation": "autorotate",
            "text-margin-x": 0,
            "text-margin-y": -10,
            "text-background-color": "#09111f",
            "text-background-opacity": 0.8,
            "text-background-padding": "3px",
            "text-border-color": "#1f2d44",
            "text-border-width": 1,
          },
        },
      ],
      layout: {
        name: "cose",
        animate: false,
        padding: 28,
        nodeRepulsion: 9000,
        idealEdgeLength: 140,
      },
    });

    return () => cy.destroy();
  }, [nodes, edges]);

  return <div className="topology-canvas" ref={containerRef} />;
}

export default TopologyGraph;
/**
 * Cytoscape-based topology renderer for link and node visualization.
 */
