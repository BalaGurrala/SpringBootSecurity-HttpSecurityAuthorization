package com.example.controller;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.entity.Course;
import com.example.service.CourseService;

//@CrossOrigin(origins = "*",  allowedHeaders ="*")
@RestController
@RequestMapping("/courses")
public class CourseController {
	
	private CourseService courseService;
	
	public CourseController(CourseService courseService) {
		this.courseService = courseService;
	}

	@GetMapping
	public List<Course> getAllCourses() {
		return this.courseService.getAllCourses();
	}
	
	@GetMapping("/{id}")
	public Course getCourse(@PathVariable("id") Long id) {
		return this.courseService.getCourse(id);
	}
	
	@PostMapping
	public Course addCourse(@RequestBody Course course) {
		return this.courseService.addCourse(course);
	}
	
	@PutMapping
	public Course updateCourse(@RequestBody Course course) {
		return this.courseService.updateCourse(course);
	}
	
	@DeleteMapping("/{id}")
	public Course deleteCourse(@PathVariable("id") Long id) {
		return this.courseService.deleteCourse(id);
	}
	
	
}
